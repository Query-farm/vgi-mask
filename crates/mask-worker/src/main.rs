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
mod meta;
mod scalar;

use vgi::catalog::{CatSchema, CatalogModel};
use vgi::Worker;

/// Worker version string, surfaced by `mask_version()`.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Catalog + schema metadata (description, provenance) surfaced to DuckDB and the
/// `vgi-lint` metadata-quality linter. The function objects themselves are served
/// from the registered scalars; this only adds catalog/schema-level comments and
/// tags.
fn catalog_metadata(name: &str) -> CatalogModel {
    CatalogModel {
        name: name.to_string(),
        comment: Some(
            "Reversible format-preserving encryption, deterministic tokenization, and \
             irreversible partial redaction of sensitive values."
                .to_string(),
        ),
        tags: vec![
            (
                "vgi.title".to_string(),
                "Data Masking & De-identification".to_string(),
            ),
            (
                "vgi.keywords".to_string(),
                "mask, masking, de-identification, anonymization, pseudonymization, PII, \
                 format-preserving encryption, FPE, tokenization, redaction, encrypt, decrypt, \
                 credit card, SSN, email, GDPR, HIPAA, data privacy"
                    .to_string(),
            ),
            (
                "vgi.description_llm".to_string(),
                "Mask sensitive values in SQL three ways: (1) format-preserving encryption \
                 (mask_fpe / mask_unfpe) that reversibly encrypts a value under a key while \
                 keeping its shape — a 16-digit card stays a Luhn-valid 16-digit card, an SSN \
                 stays SSN-shaped, an email keeps its @domain; (2) deterministic tokenization \
                 (mask_token) that produces a stable, non-reversible HMAC-SHA-256 pseudonym so \
                 the same input always maps to the same token and stays joinable across tables; \
                 (3) irreversible partial redaction (mask_redact) that keeps only the last four \
                 / first four characters, an email's first char + domain, or stars everything. \
                 Use for de-identifying PII (cards, SSNs, emails, account IDs) in query results, \
                 building masked views, and generating referentially-consistent test data."
                    .to_string(),
            ),
            (
                "vgi.description_md".to_string(),
                "# mask\n\nReversible format-preserving encryption, deterministic tokenization, \
                 and irreversible partial redaction of sensitive values over Apache Arrow.\n\n\
                 Scalars: `mask_fpe`, `mask_unfpe`, `mask_token`, `mask_redact`, \
                 `mask_version`.\n\nThe crypto is real, vetted, permissively-licensed crates — \
                 FF1 (`fpe`) over AES-256 for FPE, HMAC-SHA-256 for tokenization, SHA-256 for \
                 key derivation. No hand-rolled ciphers."
                    .to_string(),
            ),
            ("vgi.author".to_string(), "Query.Farm".to_string()),
            (
                "vgi.copyright".to_string(),
                "Copyright 2026 Query Farm LLC - https://query.farm".to_string(),
            ),
            ("vgi.license".to_string(), "MIT".to_string()),
            (
                "vgi.support_contact".to_string(),
                "https://github.com/Query-farm/vgi-mask/issues".to_string(),
            ),
            (
                "vgi.support_policy_url".to_string(),
                "https://github.com/Query-farm/vgi-mask/blob/main/README.md".to_string(),
            ),
        ],
        source_url: Some("https://github.com/Query-farm/vgi-mask".to_string()),
        schemas: vec![CatSchema {
            name: "main".to_string(),
            comment: Some(
                "Data-masking functions: format-preserving encryption, tokenization, and \
                 redaction."
                    .to_string(),
            ),
            tags: vec![
                ("vgi.title".to_string(), "Mask — main".to_string()),
                (
                    "vgi.keywords".to_string(),
                    "mask, masking, mask_fpe, mask_unfpe, mask_token, mask_redact, \
                     format-preserving encryption, tokenization, redaction, de-identification, \
                     PII, anonymization, pseudonymization, encrypt, decrypt"
                        .to_string(),
                ),
                // VGI123 classifying tags (bare keys: domain/category/topic) for faceting.
                ("domain".to_string(), "security".to_string()),
                ("category".to_string(), "data-masking".to_string()),
                ("topic".to_string(), "pii-de-identification".to_string()),
                (
                    "vgi.source_url".to_string(),
                    "https://github.com/Query-farm/vgi-mask/blob/main/crates/mask-worker/src/main.rs"
                        .to_string(),
                ),
                (
                    "vgi.description_llm".to_string(),
                    "Data-masking functions: format-preserving encrypt/decrypt sensitive values \
                     while preserving their shape (mask_fpe / mask_unfpe), produce stable \
                     non-reversible pseudonyms (mask_token), and irreversibly redact values \
                     (mask_redact)."
                        .to_string(),
                ),
                (
                    "vgi.description_md".to_string(),
                    "Data-masking functions (format-preserving encryption, tokenization, \
                     redaction) over Apache Arrow."
                        .to_string(),
                ),
                // VGI506 representative example queries for the schema.
                (
                    "vgi.example_queries".to_string(),
                    "SELECT mask.main.mask_fpe('4012888888881881', 'card', 'my-secret-key');\n\
                     SELECT mask.main.mask_unfpe(mask.main.mask_fpe('123-45-6789', 'ssn', 'k'), \
                     'ssn', 'k');\n\
                     SELECT mask.main.mask_token('customer-42', 'my-secret-key');\n\
                     SELECT mask.main.mask_redact('4012888888881881', 'last4');\n\
                     SELECT mask.main.mask_version();"
                        .to_string(),
                ),
            ],
            views: Vec::new(),
            macros: Vec::new(),
            tables: Vec::new(),
        }],
        ..Default::default()
    }
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
    let catalog_name =
        std::env::var("VGI_WORKER_CATALOG_NAME").unwrap_or_else(|_| "mask".to_string());

    let mut worker = Worker::new();
    scalar::register(&mut worker);
    worker.set_catalog(catalog_metadata(&catalog_name));
    worker.run();
}
