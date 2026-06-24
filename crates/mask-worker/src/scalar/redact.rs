//! `mask_redact(value VARCHAR, mode VARCHAR) -> VARCHAR`.
//!
//! Irreversible partial masking. `mode` is one of `last4`, `first4`, `email`,
//! `all`. NULL input → NULL. Unknown mode → DuckDB ERROR (a query bug).

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
use crate::mask::{self, RedactMode};

/// Guaranteed-runnable, catalog-qualified examples (VGI509). Each `sql` is
/// self-contained and re-runnable against an attached `mask` worker. We omit
/// `expected_result` deliberately — the linter only needs each query to execute
/// cleanly. These cover all three masking strategies; the redaction outputs are
/// deterministic and the FPE round-trip recovers its input.
const EXECUTABLE_EXAMPLES: &str = r#"[
  {
    "description": "Irreversibly redact a card number, keeping only the last four digits.",
    "sql": "SELECT mask.main.mask_redact('4012888888881881', 'last4') AS redacted"
  },
  {
    "description": "Redact an email, keeping only the first local character and the domain.",
    "sql": "SELECT mask.main.mask_redact('alice@example.com', 'email') AS redacted"
  },
  {
    "description": "Format-preserving encrypt a card number into another Luhn-valid 16-digit card.",
    "sql": "SELECT mask.main.mask_fpe('4012888888881881', 'card', 'my-secret-key') AS encrypted"
  },
  {
    "description": "Round-trip an SSN: mask_unfpe reverses mask_fpe under the same key.",
    "sql": "SELECT mask.main.mask_unfpe(mask.main.mask_fpe('123-45-6789', 'ssn', 'k'), 'ssn', 'k') AS recovered"
  },
  {
    "description": "Produce a stable, non-reversible pseudonym for an account ID.",
    "sql": "SELECT mask.main.mask_token('customer-42', 'my-secret-key') AS token"
  }
]"#;

pub struct MaskRedact;

impl ScalarFunction for MaskRedact {
    fn name(&self) -> &str {
        "mask_redact"
    }

    fn metadata(&self) -> FunctionMetadata {
        let mut tags = crate::meta::object_tags(
            "Irreversible Partial Redaction",
            "Irreversibly partially mask a value. Mode 'last4' keeps only the last four \
             characters (stars the rest), 'first4' keeps the first four, 'email' keeps the first \
             local character plus the @domain, and 'all' stars everything. The original value \
             cannot be recovered. Use for display masking of cards, SSNs, emails, and other PII. \
             NULL input returns NULL; an unknown mode raises an error.",
            "Irreversibly redact a value, e.g. `mask_redact('4012888888881881', 'last4')` → \
             `************1881`. Modes: `last4`, `first4`, `email`, `all`.",
            "mask_redact, redact, redaction, partial masking, star out, last4, first4, mask email, \
             display masking, de-identify, irreversible, obfuscate",
            "scalar/redact.rs",
        );
        // VGI509: at least one object carries runnable, catalog-qualified examples.
        tags.push(("vgi.executable_examples".into(), EXECUTABLE_EXAMPLES.into()));
        FunctionMetadata {
            description: "Irreversible partial masking: mode 'last4' keeps the last four \
                          characters, 'first4' the first four, 'email' the first local char + \
                          domain, 'all' stars everything"
                .into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT mask.main.mask_redact('4012888888881881', 'last4');".into(),
                description: "Irreversibly redact a card number, keeping only the last four \
                              digits (************1881)."
                    .into(),
                expected_output: None,
            }],
            tags,
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::any_column("value", 0, "Value to redact (VARCHAR)"),
            ArgSpec::any_column(
                "mode",
                1,
                "Redaction mode: last4/first4/email/all (VARCHAR)",
            ),
        ]
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let value = batch.column(0);
        let mode = batch.column(1);
        let rows = batch.num_rows();
        let mut out = StringBuilder::new();
        for i in 0..rows {
            match (text_str(value, i)?, text_str(mode, i)?) {
                (Some(v), Some(m)) => {
                    let mode =
                        RedactMode::parse(m).map_err(|e| RpcError::value_error(e.to_string()))?;
                    out.append_value(mask::redact(v, mode));
                }
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
    fn redacts() {
        let out = run_scalar(&MaskRedact, &[&[Some("1234567890")], &[Some("last4")]]).unwrap();
        assert_eq!(out, vec![Some("******7890".to_string())]);
    }

    #[test]
    fn null_passes_through() {
        let out = run_scalar(&MaskRedact, &[&[None], &[Some("last4")]]).unwrap();
        assert_eq!(out, vec![None]);
    }

    #[test]
    fn unknown_mode_errors() {
        let r = run_scalar(&MaskRedact, &[&[Some("x")], &[Some("bogus")]]);
        assert!(r.is_err());
    }
}
