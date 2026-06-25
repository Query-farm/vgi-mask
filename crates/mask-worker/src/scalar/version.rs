//! `mask_version()` — return the worker's version string.

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use arrow_schema::DataType;
use vgi::{
    ArgSpec, BindParams, BindResponse, FunctionExample, FunctionMetadata, ProcessParams,
    ScalarFunction,
};
use vgi_rpc::{Result, RpcError};

pub struct MaskVersion;

impl ScalarFunction for MaskVersion {
    fn name(&self) -> &str {
        "mask_version"
    }

    fn metadata(&self) -> FunctionMetadata {
        FunctionMetadata {
            description: "Returns the mask worker version string".into(),
            return_type: Some(DataType::Utf8),
            examples: vec![FunctionExample {
                sql: "SELECT mask.main.mask_version();".into(),
                description: "Return the mask worker's version string.".into(),
                expected_output: None,
            }],
            tags: crate::meta::object_tags(
                "Mask Worker Version String",
                "## `mask_version()`\n\n\
                 Returns the semantic version string of the running **mask** worker binary.\n\n\
                 ### When to use\n\
                 Use it for diagnostics — confirming which build of the worker DuckDB has attached, \
                 reporting versions in bug reports, or gating client behavior on a known release. \
                 It takes no arguments and reads no data, so it always executes regardless of keys \
                 or input rows.\n\n\
                 ### Inputs\n\
                 None.\n\n\
                 ### Output\n\
                 A VARCHAR semantic-version string (e.g. `0.1.0`) taken from the crate's \
                 `CARGO_PKG_VERSION` at build time. The same value is returned for every row.",
                "# Mask Worker Version\n\n\
                 `mask_version()` returns the semantic version string of the running mask worker \
                 binary.\n\n\
                 ## Usage\n\n\
                 ```sql\n\
                 SELECT mask.main.mask_version(); -- e.g. '0.1.0'\n\
                 ```\n\n\
                 ## Notes\n\n\
                 - Takes no arguments and is constant for a given build, so it is handy as a \
                 connectivity/diagnostics check.",
                &[
                    "version",
                    "build version",
                    "mask_version",
                    "diagnostics",
                    "worker version",
                    "semver",
                ],
            ),
            ..Default::default()
        }
    }

    fn argument_specs(&self) -> Vec<ArgSpec> {
        Vec::new()
    }

    fn on_bind(&self, _params: &BindParams) -> Result<BindResponse> {
        Ok(BindResponse::result(DataType::Utf8))
    }

    fn process(&self, params: &ProcessParams, batch: &RecordBatch) -> Result<RecordBatch> {
        let rows = batch.num_rows();
        let out: ArrayRef = Arc::new(StringArray::from(vec![crate::version(); rows]));
        RecordBatch::try_new(params.output_schema.clone(), vec![out])
            .map_err(|e| RpcError::runtime_error(e.to_string()))
    }
}
