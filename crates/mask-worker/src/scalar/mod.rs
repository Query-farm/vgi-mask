//! Scalar functions exposed by the mask worker, registered under `mask.main`.
//! All are POSITIONAL-only, per VGI convention (named args are table-only).

mod fpe;
mod redact;
mod token;
mod version;

use vgi::Worker;

/// Register every scalar function on the worker.
pub fn register(worker: &mut Worker) {
    worker.register_scalar(version::MaskVersion);
    worker.register_scalar(fpe::MaskFpe);
    worker.register_scalar(fpe::MaskUnfpe);
    worker.register_scalar(token::MaskToken);
    worker.register_scalar(redact::MaskRedact);
}
