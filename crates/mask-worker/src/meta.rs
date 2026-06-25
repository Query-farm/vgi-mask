//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function.
//!
//! Each function surfaces these in its `FunctionMetadata.tags`:
//! - `vgi.title` (VGI124)        — human-friendly display name
//! - `vgi.doc_llm` (VGI112)      — Markdown narrative aimed at LLMs/agents
//! - `vgi.doc_md` (VGI113)       — Markdown narrative for human docs
//! - `vgi.keywords` (VGI126/VGI138) — a JSON array of search terms/synonyms
//!
//! Provenance (`vgi.source_url`) is deliberately **not** repeated per object:
//! VGI139 wants it set once, on the catalog (the worker's repo), so per-object
//! copies are redundant.

/// Encode a list of keywords as the JSON-array string `vgi.keywords` expects
/// (VGI138): e.g. `["mask", "FPE"]`. Each keyword is JSON-escaped.
pub fn keywords_json(keywords: &[&str]) -> String {
    let mut out = String::from("[");
    for (i, kw) in keywords.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('"');
        for ch in kw.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                _ => out.push(ch),
            }
        }
        out.push('"');
    }
    out.push(']');
    out
}

/// Build the four standard per-object discovery/description tags.
///
/// `keywords` is encoded as a JSON array (VGI138). Provenance is intentionally
/// omitted here and lives only on the catalog object (VGI139).
pub fn object_tags(
    title: &str,
    doc_llm: &str,
    doc_md: &str,
    keywords: &[&str],
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), doc_llm.to_string()),
        ("vgi.doc_md".to_string(), doc_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
    ]
}
