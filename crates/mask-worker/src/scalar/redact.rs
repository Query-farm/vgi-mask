//! `mask_redact(value VARCHAR, mode VARCHAR) -> VARCHAR`.
//!
//! Irreversible partial masking. `mode` is one of `last4`, `first4`, `email`,
//! `all`. NULL input → NULL. Unknown mode → DuckDB ERROR (a query bug).

use std::sync::Arc;

use arrow_array::builder::StringBuilder;
use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::DataType;
use vgi::{ArgSpec, BindParams, BindResponse, FunctionMetadata, ProcessParams, ScalarFunction};
use vgi_rpc::{Result, RpcError};

use crate::arrow_io::text_str;
use crate::mask::{self, RedactMode};

pub struct MaskRedact;

impl ScalarFunction for MaskRedact {
    fn name(&self) -> &str {
        "mask_redact"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Irreversible partial masking: mode 'last4' keeps the last four \
                          characters, 'first4' the first four, 'email' the first local char + \
                          domain, 'all' stars everything"
                .into(),
            return_type: Some(DataType::Utf8),
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
