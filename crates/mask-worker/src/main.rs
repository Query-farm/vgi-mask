//! The `mask` VGI worker.
//!
//! A standalone binary that DuckDB launches and talks to over Apache Arrow IPC
//! (`ATTACH 'mask' (TYPE vgi, LOCATION '…')`). It brings reversible
//! format-preserving encryption, deterministic tokenization, and irreversible
//! partial redaction of sensitive values to SQL under the catalog `mask`, schema
//! `main`:
//!
//! ```sql
//! ATTACH 'mask' (TYPE vgi, LOCATION './target/release/mask-worker');
//! SET search_path = 'mask.main';
//!
//! SELECT mask_fpe('4012888888881881', 'card', 'k');   -- 16-digit, Luhn-valid
//! SELECT mask_unfpe(mask_fpe('123-45-6789','ssn','k'), 'ssn', 'k');  -- 123-45-6789
//! SELECT mask_token('customer-42', 'k');              -- stable pseudonym
//! SELECT mask_redact('123456789', 'last4');           -- *****6789
//! ```
//!
//! The pure engine (FF1 FPE, HMAC tokenization, redaction) lives in `mask.rs`;
//! the `scalar/` modules are thin Arrow adapters over it. Scalars are
//! POSITIONAL-only, per VGI convention.

mod arrow_io;
mod mask;
mod scalar;

use vgi::Worker;

/// Worker version string, surfaced by `mask_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn main() {
    // Logs MUST go to stderr — stdout is the Arrow-IPC channel.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().filter_or("VGI_LOG", "info"))
        .format_timestamp_millis()
        .try_init();

    // The catalog name DuckDB sees in `ATTACH 'mask' (TYPE vgi, …)`. Default to
    // `mask`, but honor an explicit override so a test harness can rename it.
    if std::env::var_os("VGI_WORKER_CATALOG_NAME").is_none() {
        std::env::set_var("VGI_WORKER_CATALOG_NAME", "mask");
    }

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    worker.run();
}
