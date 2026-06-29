//! `mask_fpe(value VARCHAR, format VARCHAR, key VARCHAR) -> VARCHAR` and its
//! inverse `mask_unfpe(value, format, key) -> VARCHAR`.
//!
//! Format-preserving encryption: the output keeps the input's shape (a 16-digit
//! card stays a Luhn-valid 16-digit card, an SSN stays SSN-shaped, an email keeps
//! its `@domain`). `mask_unfpe` reverses `mask_fpe` under the same key + format.
//!
//! ## NULL-vs-error policy
//!
//! - **NULL input** → NULL output (missing data flows through).
//! - **Unknown `format`** → DuckDB **ERROR**: the caller named a profile that does
//!   not exist — a query bug, not dirty data, so fail loudly.
//! - **Empty `key`** → DuckDB **ERROR**: an empty key is almost certainly a
//!   mistake and would make every secret the same.
//! - A value too short to encrypt under its profile is **passed through unchanged**
//!   (small-domain policy, documented in `mask.rs` and the README); it still
//!   round-trips.

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::text_str;
use crate::mask::{self, Format};

/// Shared driver for `mask_fpe` (forward) and `mask_unfpe` (inverse).
fn run_fpe(params: &ProcessParams, batch: &RecordBatch, forward: bool) -> Result<RecordBatch> {
    let value = batch.column(0);
    let fmt = batch.column(1);
    let key = batch.column(2);
    let rows = batch.num_rows();
    let mut out = StringBuilder::new();
    for i in 0..rows {
        match (text_str(value, i)?, text_str(fmt, i)?, text_str(key, i)?) {
            (Some(v), Some(fmt_name), Some(k)) => {
                // Unknown format / empty key are loud errors.
                let format =
                    Format::parse(fmt_name).map_err(|e| RpcError::value_error(e.to_string()))?;
                let res = if forward {
                    mask::fpe_encrypt(v, format, k)
                } else {
                    mask::fpe_decrypt(v, format, k)
                };
                match res {
                    Ok(s) => out.append_value(&s),
                    Err(e) => return Err(RpcError::value_error(e.to_string())),
                }
            }
            // Any NULL operand → NULL result.
            _ => out.append_null(),
        }
    }
    let arr: ArrayRef = Arc::new(out.finish());
    RecordBatch::try_new(params.output_schema.clone(), vec![arr])
        .map_err(|e| RpcError::runtime_error(e.to_string()))
}

fn fpe_arg_specs() -> Vec<ArgSpec> {
    vec![
        ArgSpec::column(
            "value",
            0,
            "varchar",
            "The sensitive string to transform; its shape is preserved and NULL flows through to NULL",
        ),
        ArgSpec::column(
            "format",
            1,
            "varchar",
            "Shape profile selecting which characters are encryptable and what structure to keep: \
             'card', 'ssn', 'digits', 'alnum', or 'email'",
        ),
        ArgSpec::column(
            "key",
            2,
            "varchar",
            "Secret key the AES key is derived from (via SHA-256); the same key reverses mask_fpe, \
             and an empty key is rejected",
        ),
    ]
}

pub struct MaskFpe;

impl ScalarFunction for MaskFpe {
    fn name(&self) -> &str {
        "mask_fpe"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Format-preserving encrypt a value under a shape profile \
                          (card/ssn/digits/alnum/email) and key; output keeps the input shape"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT mask.main.mask_fpe('4012888888881881', 'card', 'my-secret-key');"
                    .into(),
                description: "Format-preserving encrypt a credit-card number; the result is a \
                              different but still Luhn-valid 16-digit card."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Format-Preserving Encrypt Value",
                "## `mask_fpe(value, format, key)`\n\n\
                 Reversibly encrypts a sensitive string under a secret `key` using **FF1 \
                 format-preserving encryption** (FF1 over AES-256), so the ciphertext keeps the \
                 *shape* of the input and can be substituted wherever the original was used.\n\n\
                 ### When to use\n\
                 Reach for this when you need to de-identify PII but downstream consumers still \
                 expect the original format — masked views over cards/SSNs/emails, generating \
                 referentially-consistent test data, or sharing data while keeping it reversible \
                 for authorized holders of the key. If you never need to recover the value, prefer \
                 `mask_token` (one-way pseudonym) or `mask_redact` (display masking).\n\n\
                 ### Inputs\n\
                 - `value` — the string to encrypt (VARCHAR). NULL passes through to NULL.\n\
                 - `format` — shape profile: `card`, `ssn`, `digits`, `alnum`, or `email`.\n\
                 - `key` — secret key string; the AES key is derived from it via SHA-256.\n\n\
                 ### Output\n\
                 A VARCHAR ciphertext with the same shape as the input. `card` stays a Luhn-valid \
                 16-digit number, `ssn` keeps its dashes, `email` keeps `@domain` and FPEs only the \
                 local part, `digits`/`alnum` keep their length and character class.\n\n\
                 ### Behavior & edge cases\n\
                 - Reverse with `mask_unfpe` under the **same** `format` and `key`.\n\
                 - **Small-domain pass-through:** FF1 refuses domains below 1,000,000 (radix 10 ⇒ \
                 fewer than 6 digits; radix 62 ⇒ fewer than 4 chars), so very short values are \
                 returned unchanged — they still round-trip.\n\
                 - NULL input → NULL; an unknown `format` or an empty `key` raises an error.",
                "# Format-Preserving Encrypt\n\n\
                 `mask_fpe(value, format, key)` reversibly encrypts a value while preserving its \
                 shape, using FF1 format-preserving encryption over AES-256.\n\n\
                 ## Usage\n\n\
                 ```sql\n\
                 -- card stays a Luhn-valid 16-digit number\n\
                 SELECT mask.main.mask_fpe('4012888888881881', 'card', 'my-secret-key');\n\
                 -- SSN keeps its dashes\n\
                 SELECT mask.main.mask_fpe('123-45-6789', 'ssn', 'my-secret-key');\n\
                 ```\n\n\
                 The `format` profile selects the shape to preserve: `card`, `ssn`, `digits`, \
                 `alnum`, or `email`.\n\n\
                 ## Notes\n\n\
                 - Reverse the transform with `mask_unfpe` under the same `format` and `key`.\n\
                 - Values too short for FF1's minimum domain are passed through unchanged but still \
                 round-trip.\n\
                 - NULL in → NULL out; an unknown format or empty key is an error.",
                &[
                    "mask_fpe",
                    "format-preserving encryption",
                    "FPE",
                    "FF1",
                    "encrypt",
                    "tokenize card",
                    "mask credit card",
                    "mask SSN",
                    "mask email",
                    "reversible masking",
                    "de-identify",
                    "anonymize",
                ],
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        fpe_arg_specs()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        run_fpe(params, batch, true)
    }
}

pub struct MaskUnfpe;

impl ScalarFunction for MaskUnfpe {
    fn name(&self) -> &str {
        "mask_unfpe"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Inverse of mask_fpe: recover the original value under the same \
                          format profile and key"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT mask.main.mask_unfpe(\
                      mask.main.mask_fpe('123-45-6789', 'ssn', 'my-secret-key'), \
                      'ssn', 'my-secret-key');"
                    .into(),
                description: "Round-trip an SSN: mask_unfpe reverses mask_fpe under the same \
                              format and key, recovering '123-45-6789'."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Format-Preserving Decrypt Value",
                "## `mask_unfpe(value, format, key)`\n\n\
                 The **inverse of `mask_fpe`**: recovers the original plaintext from a \
                 format-preserving ciphertext using FF1 decryption over AES-256.\n\n\
                 ### When to use\n\
                 Use this on the authorized side of a masking pipeline to recover a value that was \
                 protected with `mask_fpe`. It only succeeds when you supply the **same** `format` \
                 profile and the **same** `key` that produced the ciphertext — a different key \
                 yields different (wrong) output, which is the point of keyed encryption.\n\n\
                 ### Inputs\n\
                 - `value` — the format-preserving ciphertext to reverse (VARCHAR).\n\
                 - `format` — the profile used to encrypt: `card`, `ssn`, `digits`, `alnum`, or \
                 `email`.\n\
                 - `key` — the same secret key that was used with `mask_fpe`.\n\n\
                 ### Output\n\
                 The recovered original VARCHAR value.\n\n\
                 ### Behavior & edge cases\n\
                 - For `card`, decryption re-derives the Luhn check digit, so the original \
                 16-digit number is reproduced exactly.\n\
                 - Values that were passed through unchanged by `mask_fpe` (small-domain rule) \
                 decrypt to themselves.\n\
                 - NULL input → NULL; an unknown `format` or an empty `key` raises an error.",
                "# Format-Preserving Decrypt\n\n\
                 `mask_unfpe(value, format, key)` reverses `mask_fpe`, recovering the original \
                 value from a format-preserving ciphertext.\n\n\
                 ## Usage\n\n\
                 ```sql\n\
                 SELECT mask.main.mask_unfpe(\n\
                 \u{20}\u{20}mask.main.mask_fpe('123-45-6789', 'ssn', 'k'), 'ssn', 'k');\n\
                 -- => '123-45-6789'\n\
                 ```\n\n\
                 ## Notes\n\n\
                 - You must pass the same `format` and `key` used to encrypt; a different key \
                 produces incorrect output.\n\
                 - `card` decryption re-derives the Luhn check digit so the round-trip is exact.\n\
                 - NULL in → NULL out; an unknown format or empty key is an error.",
                &[
                    "mask_unfpe",
                    "decrypt",
                    "format-preserving decryption",
                    "FPE",
                    "FF1",
                    "reverse mask",
                    "unmask",
                    "recover original",
                    "round-trip",
                ],
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        fpe_arg_specs()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        run_fpe(params, batch, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::run_scalar;

    #[test]
    fn binds_utf8() {
        let bind = BindParams::default();
        assert_eq!(
            MaskFpe
                .on_bind(&bind)
                .unwrap()
                .output_schema
                .field(0)
                .data_type(),
            &DataType::Utf8
        );
    }

    #[test]
    fn roundtrip_via_arrow() {
        let vals = &[
            Some("4012888888881881"),
            Some("123-45-6789"),
            Some("alice@example.com"),
        ];
        let fmts = &[Some("card"), Some("ssn"), Some("email")];
        let keys = &[Some("k"), Some("k"), Some("k")];
        let enc = run_scalar(&MaskFpe, &[vals, fmts, keys]).unwrap();
        let enc_refs: Vec<Option<&str>> = enc.iter().map(|o| o.as_deref()).collect();
        let dec = run_scalar(&MaskUnfpe, &[&enc_refs, fmts, keys]).unwrap();
        let dec_refs: Vec<Option<&str>> = dec.iter().map(|o| o.as_deref()).collect();
        assert_eq!(dec_refs, vals.to_vec());
        // and encryption changed the values
        assert_ne!(enc[0].as_deref(), Some("4012888888881881"));
    }

    #[test]
    fn null_passes_through() {
        let out = run_scalar(&MaskFpe, &[&[None], &[Some("card")], &[Some("k")]]).unwrap();
        assert_eq!(out, vec![None]);
    }

    #[test]
    fn unknown_format_errors() {
        let r = run_scalar(
            &MaskFpe,
            &[&[Some("123456")], &[Some("bogus")], &[Some("k")]],
        );
        assert!(r.is_err(), "unknown format must raise an error");
    }

    #[test]
    fn empty_key_errors() {
        let r = run_scalar(
            &MaskFpe,
            &[&[Some("123456")], &[Some("digits")], &[Some("")]],
        );
        assert!(r.is_err(), "empty key must raise an error");
    }
}
