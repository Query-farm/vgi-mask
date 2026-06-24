//! `mask_token(value VARCHAR, key VARCHAR) -> VARCHAR`.
//!
//! A deterministic pseudonym (HMAC-SHA-256, hex, 128-bit). Same input + key ⇒
//! same token, so tokens preserve referential integrity for cross-table joins.
//! Not reversible.
//!
//! NULL input → NULL. Empty key → DuckDB ERROR (same rationale as `mask_fpe`).

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
use crate::mask;

pub struct MaskToken;

impl ScalarFunction for MaskToken {
    fn name(&self) -> &str {
        "mask_token"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Deterministic pseudonym (HMAC-SHA-256) of a value under a key; same \
                          input+key yields the same token, so it is joinable across tables. \
                          Not reversible."
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT mask.main.mask_token('customer-42', 'my-secret-key');".into(),
                description: "Produce a stable, non-reversible pseudonym for an account ID; the \
                              same input and key always yield the same token, so it stays \
                              joinable across tables."
                    .into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Deterministic Tokenize Value",
                "## `mask_token(value, key)`\n\n\
                 Produces a stable, **one-way pseudonym** for a value using **HMAC-SHA-256** under \
                 a secret `key`, returned as a hex string. The mapping is deterministic: the same \
                 `value` and `key` always yield the same token.\n\n\
                 ### When to use\n\
                 Choose tokenization when you need to de-identify an identifier *and* keep it \
                 joinable. Because identical inputs map to identical tokens, you can replace an \
                 account ID or email with its token in two different tables and still join on it — \
                 referential integrity is preserved without ever exposing the original. Unlike \
                 `mask_fpe`, this is **not reversible**; unlike `mask_redact`, it does not preserve \
                 the input's shape.\n\n\
                 ### Inputs\n\
                 - `value` — the identifier to tokenize (VARCHAR). NULL passes through to NULL.\n\
                 - `key` — secret key string; the HMAC key is domain-separated from the FPE key.\n\n\
                 ### Output\n\
                 A hexadecimal HMAC-SHA-256 token (VARCHAR). The original value cannot be \
                 recovered from it.\n\n\
                 ### Behavior & edge cases\n\
                 - Deterministic and collision-resistant; same input+key ⇒ same token across runs \
                 and tables, so it is safe for joins.\n\
                 - **Caution:** deterministic tokens are frequency-analyzable on low-cardinality \
                 columns — equal inputs always produce equal tokens.\n\
                 - NULL input → NULL; an empty `key` raises an error.",
                "# Deterministic Tokenize\n\n\
                 `mask_token(value, key)` returns a stable, non-reversible HMAC-SHA-256 pseudonym \
                 for a value, as a hex string.\n\n\
                 ## Usage\n\n\
                 ```sql\n\
                 SELECT mask.main.mask_token('customer-42', 'my-secret-key');\n\
                 ```\n\n\
                 The same input and key always produce the same token, so tokens stay joinable \
                 across tables.\n\n\
                 ## Notes\n\n\
                 - Tokens are one-way: the original value cannot be recovered (use `mask_fpe` if \
                 you need reversibility).\n\
                 - Deterministic output is frequency-analyzable on low-cardinality data.\n\
                 - NULL in → NULL out; an empty key is an error.",
                "mask_token, tokenize, tokenization, pseudonym, pseudonymization, HMAC, \
                 deterministic masking, joinable, referential integrity, de-identify, hash",
                "scalar/token.rs",
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::any_column("value", 0, "Value to tokenize (VARCHAR)"),
            ArgSpec::any_column("key", 1, "Secret key string (VARCHAR)"),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let value = batch.column(0);
        let key = batch.column(1);
        let rows = batch.num_rows();
        let mut out = StringBuilder::new();
        for i in 0..rows {
            match (text_str(value, i)?, text_str(key, i)?) {
                (Some(v), Some(k)) => match mask::token(v, k) {
                    Ok(t) => out.append_value(&t),
                    Err(e) => return Err(RpcError::value_error(e.to_string())),
                },
                _ => out.append_null(),
            }
        }
        let arr: ArrayRef = Arc::new(out.finish());
        RecordBatch::try_new(params.output_schema.clone(), vec![arr])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arrow_io::test_support::run_scalar;

    #[test]
    fn deterministic_and_joinable() {
        let a = run_scalar(&MaskToken, &[&[Some("acct-1")], &[Some("k")]]).unwrap();
        let b = run_scalar(&MaskToken, &[&[Some("acct-1")], &[Some("k")]]).unwrap();
        assert_eq!(a, b);
        let c = run_scalar(&MaskToken, &[&[Some("acct-2")], &[Some("k")]]).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn null_passes_through() {
        let out = run_scalar(&MaskToken, &[&[None], &[Some("k")]]).unwrap();
        assert_eq!(out, vec![None]);
    }

    #[test]
    fn empty_key_errors() {
        let r = run_scalar(&MaskToken, &[&[Some("x")], &[Some("")]]);
        assert!(r.is_err());
    }
}
