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
        ArgSpec::any_column("value", 0, "Value to transform (VARCHAR)"),
        ArgSpec::any_column(
            "format",
            1,
            "Shape profile: 'card', 'ssn', 'digits', 'alnum', or 'email' (VARCHAR)",
        ),
        ArgSpec::any_column("key", 2, "Secret key string (VARCHAR)"),
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
