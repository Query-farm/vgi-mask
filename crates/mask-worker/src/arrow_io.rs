//! Small Arrow helpers shared across the scalar functions: reading VARCHAR input
//! cells. The in-process test harness below drives a `ScalarFunction` end-to-end
//! without the RPC/IPC plumbing.

use arrow_array::cast::AsArray;
use arrow_array::{Array, ArrayRef};
use arrow_schema::DataType;
use vgi_rpc::{Result, RpcError};

/// Borrow the UTF-8 text of a VARCHAR cell at `row`, or `None` if null. Errors if
/// the column isn't a string type.
pub fn text_str(col: &ArrayRef, row: usize) -> Result<Option<&str>> {
    if col.is_null(row) {
        return Ok(None);
    }
    Ok(Some(match col.data_type() {
        DataType::Utf8 => col.as_string::<i32>().value(row),
        DataType::LargeUtf8 => col.as_string::<i64>().value(row),
        other => {
            return Err(RpcError::value_error(format!(
                "expected a VARCHAR (string) argument, got {other:?}"
            )))
        }
    }))
}

/// Test-only helpers shared by the scalar Arrow-boundary unit tests. These let a
/// `#[cfg(test)]` block drive a `ScalarFunction` end to end in-process (build the
/// input `RecordBatch`, run `on_bind` + `process`, inspect the result) without the
/// RPC/IPC plumbing.
#[cfg(test)]
pub mod test_support {
    use std::sync::Arc;

    use arrow_array::cast::AsArray;
    use arrow_array::{Array, ArrayRef, RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema, SchemaRef};
    use vgi::arguments::Arguments;
    use vgi::{BindParams, ProcessParams, ScalarFunction};
    use vgi_rpc::Result;

    /// Build a multi-column `Utf8` (VARCHAR) input batch from columns of optional
    /// strings. All columns must have the same length.
    pub fn text_batch(cols: &[&[Option<&str>]]) -> RecordBatch {
        let mut fields = Vec::new();
        let mut arrays: Vec<ArrayRef> = Vec::new();
        for (i, col) in cols.iter().enumerate() {
            let arr: ArrayRef = Arc::new(StringArray::from(col.to_vec()));
            fields.push(Field::new(format!("c{i}"), DataType::Utf8, true));
            arrays.push(arr);
        }
        let schema = Arc::new(Schema::new(fields));
        RecordBatch::try_new(schema, arrays).unwrap()
    }

    /// Build a `ProcessParams` carrying the given output schema and arguments.
    pub fn process_params(output_schema: SchemaRef, arguments: Arguments) -> ProcessParams {
        ProcessParams {
            output_schema,
            input_schema: None,
            execution_id: Vec::new(),
            init_opaque_data: Vec::new(),
            arguments,
            settings: Default::default(),
            secrets: Default::default(),
            auth_principal: None,
            projection_ids: None,
            pushdown_filters: None,
            join_keys: Vec::new(),
            storage: None,
            order_by_column: None,
            order_by_direction: None,
            order_by_null_order: None,
            order_by_limit: None,
            tablesample_percentage: None,
            tablesample_seed: None,
            attach_opaque_data: None,
            at_unit: None,
            at_value: None,
        }
    }

    /// Run a scalar function over a multi-column VARCHAR batch: call `on_bind` to
    /// obtain the declared output schema, then `process`, returning the result
    /// column as a `Vec<Option<String>>`.
    pub fn run_scalar(
        f: &dyn ScalarFunction,
        cols: &[&[Option<&str>]],
    ) -> Result<Vec<Option<String>>> {
        let batch = text_batch(cols);
        let bind = BindParams {
            input_schema: Some(batch.schema()),
            arguments: Arguments::default(),
            ..Default::default()
        };
        let bound = f.on_bind(&bind)?;
        let params = process_params(bound.output_schema, Arguments::default());
        let out = f.process(&params, &batch)?;
        let s = out.column(0).as_string::<i32>();
        Ok((0..s.len())
            .map(|i| {
                if s.is_null(i) {
                    None
                } else {
                    Some(s.value(i).to_string())
                }
            })
            .collect())
    }
}
