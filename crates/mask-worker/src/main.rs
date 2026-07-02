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

/// VGI152/VGI920 agent-check suite (catalog `vgi.agent_test_tasks`). A JSON array
/// of `{name, prompt, reference_sql}` analyst tasks. `vgi-lint simulate` runs an
/// agent through each prompt using only the worker's metadata, then compares its
/// SQL's result to `reference_sql`. Every reference query is deterministic: the
/// redaction outputs are exact strings, the FPE round-trip recovers its own input,
/// and tokenization determinism / card shape are checked as booleans — so the
/// key-dependence of ciphertext never makes a task flaky.
const AGENT_TEST_TASKS: &str = r#"[
  {
    "name": "redact_card_last4",
    "prompt": "Redact the credit-card number '4012888888881881' so that only its last four digits stay visible and every earlier character is starred out. Return only the single redacted string as one column.",
    "reference_sql": "SELECT mask.main.mask_redact('4012888888881881', 'last4')",
    "ignore_column_names": true
  },
  {
    "name": "redact_email_for_display",
    "prompt": "Mask the email address 'alice@example.com' so that only the first character of the local part and the whole @domain remain, with the rest of the local part starred out. Return only the single masked string as one column.",
    "reference_sql": "SELECT mask.main.mask_redact('alice@example.com', 'email')",
    "ignore_column_names": true
  },
  {
    "name": "fpe_roundtrip_ssn",
    "prompt": "Using the secret key 'k', reversibly format-preserving-encrypt the Social Security number '123-45-6789' and then decrypt that result back with the same key and profile. Return only the single recovered value as one column.",
    "reference_sql": "SELECT mask.main.mask_unfpe(mask.main.mask_fpe('123-45-6789', 'ssn', 'k'), 'ssn', 'k')",
    "ignore_column_names": true
  },
  {
    "name": "token_pseudonym",
    "prompt": "Produce the deterministic, non-reversible pseudonym (token) for the account identifier 'customer-42' using the secret key 'k'. Return only the single token as one column.",
    "reference_sql": "SELECT mask.main.mask_token('customer-42', 'k')",
    "ignore_column_names": true
  },
  {
    "name": "fpe_card",
    "prompt": "Using the secret key 'k' and the 'card' shape profile, format-preserving-encrypt the credit-card number '4012888888881881' so the result is another 16-digit card. Return only the single encrypted card number as one column.",
    "reference_sql": "SELECT mask.main.mask_fpe('4012888888881881', 'card', 'k')",
    "ignore_column_names": true
  }
]"#;

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
                meta::keywords_json(&[
                    "mask",
                    "masking",
                    "de-identification",
                    "anonymization",
                    "pseudonymization",
                    "PII",
                    "format-preserving encryption",
                    "FPE",
                    "tokenization",
                    "redaction",
                    "encrypt",
                    "decrypt",
                    "credit card",
                    "SSN",
                    "email",
                    "GDPR",
                    "HIPAA",
                    "data privacy",
                ]),
            ),
            (
                "vgi.doc_llm".to_string(),
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
                "vgi.doc_md".to_string(),
                "# Mask: Data Masking, Format-Preserving Encryption & PII De-identification in SQL\n\n\
                 ![RustCrypto logo](https://avatars.githubusercontent.com/u/22351541?s=240)\n\n\
                 **Mask** brings production-grade data masking to DuckDB — reversible \
                 format-preserving encryption (FPE), deterministic tokenization, and irreversible \
                 redaction of sensitive values, all callable as plain SQL scalar functions over \
                 Apache Arrow. It is built for data engineers, analysts, and privacy teams who need \
                 to de-identify PII such as credit card numbers, Social Security numbers, email \
                 addresses, and account IDs directly in their queries, views, and pipelines, with \
                 no external service or pre-processing step.\n\n\
                 Under the hood, Mask uses real, vetted, permissively-licensed cryptography — never \
                 hand-rolled ciphers. Format-preserving encryption is implemented with the NIST \
                 [SP 800-38G](https://csrc.nist.gov/publications/detail/sp/800-38g/final) **FF1** \
                 algorithm from the [`fpe`](https://github.com/str4d/fpe) crate \
                 ([docs](https://docs.rs/fpe)), keyed with AES-256 from the \
                 [RustCrypto `aes`](https://github.com/RustCrypto/block-ciphers) crate \
                 ([docs](https://docs.rs/aes)). Deterministic tokenization uses HMAC-SHA-256, and \
                 keys are derived with SHA-256, both from the \
                 [RustCrypto](https://github.com/RustCrypto) hashing and MAC crates \
                 ([`hmac`](https://docs.rs/hmac), [`sha2`](https://docs.rs/sha2)). FPE preserves a \
                 value's *shape*: a 16-digit card stays a Luhn-valid 16-digit card, an SSN stays \
                 SSN-shaped, and an email keeps its `@domain` — so masked data still passes format \
                 validation and flows through schemas unchanged.\n\n\
                 Mask offers three complementary de-identification strategies, and you choose \
                 between them based on whether the original value must be recoverable later. \
                 **Reversible format-preserving encryption** protects a value under a secret key \
                 while keeping its shape, so authorized holders of the key can recover it and \
                 downstream format checks still pass — ideal for masked views, reversible data \
                 sharing, and generating referentially-consistent synthetic test data that mirrors \
                 production shape. **Deterministic tokenization** replaces an identifier with a \
                 stable, non-reversible HMAC-SHA-256 pseudonym so equal inputs always map to equal \
                 tokens and masked columns stay joinable across tables for analytics without ever \
                 exposing the real value. **Irreversible redaction** stars out the sensitive \
                 portion of a value for human-facing display, keeping only a small non-secret hint \
                 such as the last four digits. Mask \
                 supports GDPR- and HIPAA-driven anonymization and pseudonymization workflows; note \
                 that key management (KMS/HSM, rotation) is intentionally out of scope — the worker \
                 simply takes a key. Learn more about \
                 [format-preserving encryption](https://en.wikipedia.org/wiki/Format-preserving_encryption) \
                 and the [RustCrypto](https://www.rustcrypto.org/) project that powers Mask."
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
            // VGI152 agent-check suite: deterministic analyst tasks that `vgi-lint
            // simulate` runs an agent through to measure how usable this worker is.
            // Every reference_sql yields a stable result (redaction outputs are exact;
            // the FPE round-trip recovers its input; tokenization determinism and card
            // shape are asserted as booleans), so ciphertext key-dependence never makes
            // a task flaky.
            (
                "vgi.agent_test_tasks".to_string(),
                AGENT_TEST_TASKS.to_string(),
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
                    meta::keywords_json(&[
                        "mask",
                        "masking",
                        "mask_fpe",
                        "mask_unfpe",
                        "mask_token",
                        "mask_redact",
                        "format-preserving encryption",
                        "tokenization",
                        "redaction",
                        "de-identification",
                        "PII",
                        "anonymization",
                        "pseudonymization",
                        "encrypt",
                        "decrypt",
                    ]),
                ),
                // VGI123 classifying tags (bare keys: domain/category/topic) for faceting.
                ("domain".to_string(), "security".to_string()),
                ("category".to_string(), "data-masking".to_string()),
                ("topic".to_string(), "pii-de-identification".to_string()),
                (
                    "vgi.doc_llm".to_string(),
                    "The `main` schema of the mask worker groups its data-masking scalar functions \
                     into three complementary strategies. Reversible format-preserving encryption \
                     keeps a value's shape while protecting it under a secret key, so authorized \
                     key holders can recover it. Deterministic tokenization produces stable, \
                     non-reversible pseudonyms that stay joinable across tables. Irreversible \
                     redaction stars out the sensitive portion of a value for display. Pick \
                     format-preserving encryption when you must reverse the value, tokenization \
                     when you need joinable pseudonyms, and redaction for one-way display masking; \
                     list the schema to discover the exact functions and their signatures."
                        .to_string(),
                ),
                (
                    "vgi.doc_md".to_string(),
                    "# mask.main\n\n\
                     Data-masking scalar functions over Apache Arrow, grouped into three \
                     complementary strategies:\n\n\
                     - **Format-preserving encryption** — reversibly protect a value under a key \
                     while keeping its shape (a card stays a Luhn-valid 16-digit card).\n\
                     - **Tokenization** — replace an identifier with a stable, non-reversible \
                     HMAC-SHA-256 pseudonym that stays joinable across tables.\n\
                     - **Redaction** — irreversibly star out the sensitive portion of a value for \
                     display.\n\n\
                     List the schema to see the available functions and their signatures."
                        .to_string(),
                ),
                // VGI413 category registry: an ordered list of the schema's function groups.
                // Each function declares a matching `vgi.category`.
                (
                    "vgi.categories".to_string(),
                    "[\n\
                     {\"name\": \"Format-Preserving Encryption\", \"description\": \"Reversibly \
                     encrypt and decrypt a value under a secret key while preserving its shape \
                     (FF1 over AES-256).\"},\n\
                     {\"name\": \"Tokenization\", \"description\": \"Replace an identifier with a \
                     stable, non-reversible HMAC-SHA-256 pseudonym that stays joinable across \
                     tables.\"},\n\
                     {\"name\": \"Redaction\", \"description\": \"Irreversibly star out the \
                     sensitive portion of a value for human-facing display.\"},\n\
                     {\"name\": \"Diagnostics\", \"description\": \"Worker introspection such as \
                     the running version string.\"}\n\
                     ]"
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
