# CLAUDE.md — vgi-mask

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion.

## What this is

A [VGI](https://query.farm) worker (Rust, compiled binary) exposing **reversible
format-preserving encryption**, **deterministic tokenization**, and **irreversible
partial redaction** of sensitive values to DuckDB/SQL over Arrow IPC. Built on the
`vgi` crate (crates.io), modeled on `vgi-units` / `vgi-charset`. Catalog name
`mask` (single `main` schema).

The crypto is real, vetted, permissively-licensed crates — **no hand-rolled
ciphers**: FF1 (`fpe`) over AES-256 (`aes`) for FPE, HMAC-SHA-256 (`hmac`+`sha2`)
for tokenization, SHA-256 for key derivation.

## Layout

```
Cargo.toml                          workspace; pins vgi = "0.5.0", arrow 58, fpe/aes/sha2/hmac/hex
crates/mask-worker/
  src/main.rs                       Worker::new(); registers the scalars
  src/lib.rs                        lib target re-exporting `mask` for integration tests
  src/mask.rs                       PURE engine (no Arrow): FF1 FPE + token + redact + unit tests
  src/arrow_io.rs                   VARCHAR cell reads + in-process scalar test harness
  src/scalar/{fpe,token,redact,version,mod}.rs   thin Arrow scalar adapters
  tests/roundtrip.rs                integration tests (round-trip, Luhn, determinism)
test/sql/{fpe,mask}.test            haybarn-unittest sqllogictest — authoritative E2E
Makefile                            test / test-unit / test-sql / lint / fmt / build / clean
```

Pattern (same as siblings): keep computation in `mask.rs` (pure, unit-tested);
keep Arrow marshalling in `arrow_io.rs` + `scalar/*.rs` (thin, harness-tested).

## The FPE model

`mask.rs` defines an `Alphabet` (ordered symbol list ⇒ stable numeral index) and
FPEs only the *encryptable* positions of a value, leaving structural characters in
place so shape is preserved:

- `digits` → radix-10 `DIGITS` alphabet (every `[0-9]`).
- `alnum` → radix-62 `ALNUM` alphabet (case-preserving `[0-9a-zA-Z]`).
- `ssn` → `DIGITS`, dashes pass through.
- `email` → split on the last `@`, FPE the local part over `ALNUM`, keep `@domain`.
- `card` → FPE the first 15 digits over `DIGITS`, then **recompute the 16th as the
  Luhn check digit** so output is Luhn-valid; decrypt re-derives the same check
  digit, so it round-trips. Non-16-digit inputs fall back to plain `digits`.

The key string is hashed to a 256-bit AES key via SHA-256 (domain-separated from
the token HMAC key). FF1 with `&[]` tweak and `FlexibleNumeralString`.

## Sharp edges

1. **`haybarn-unittest` skips `require vgi`** — `.test` files use explicit
   `statement ok` + `LOAD vgi;`, then `ATTACH 'mask' ... (TYPE vgi, LOCATION
   '${VGI_MASK_WORKER}')` and `require-env VGI_MASK_WORKER`. Run over `test/sql/*`.
   Each file ends with `USE memory; DETACH mask;`.

2. **Ciphertext is key-derivation-dependent, so SQL tests assert *properties*,
   not hardcoded ciphertext.** Round-trip (`mask_unfpe(mask_fpe(x))=x`), shape
   (`regexp_full_match` for the digit pattern), Luhn validity (computed in SQL),
   determinism (`=`), key sensitivity (`<>`). Redaction outputs *are* exact.

3. **FF1 minimum-domain rule = small-domain pass-through.** FF1 refuses
   `radix^len < 1_000_000` (radix 10 ⇒ ≥6 digits; radix 62 ⇒ ≥4 chars). When a
   value has too few encryptable characters, the engine **returns it unchanged**
   rather than panic. This is deliberate and documented (a tiny domain leaks
   anyway). Pass-through values still round-trip (decrypt is a no-op on them).

4. **NULL-vs-error policy.** NULL input → NULL (per row). Unknown `format`/`mode`
   and empty `key` → DuckDB **ERROR** (caller bugs, fail loudly). The split lives
   in the scalar adapters: `Format::parse`/`RedactMode::parse` errors and
   `MaskError::EmptyKey` map to `RpcError::value_error`.

5. **Scalars are positional-only.** `mask_fpe(value, format, key)` reads columns
   0/1/2; no named args, no arity overloads. All returns are VARCHAR, so no
   explicit `arrow_type` is needed (LIST/STRUCT/TIMESTAMPTZ would require it).

6. **bin + lib both compile `mask.rs`.** `main.rs` has `mod mask;` (binary copy);
   `lib.rs` re-exports `pub mod mask;` for `tests/`.

7. **Only FF1, no FF3-1.** The `fpe` crate has no FF3-1, and FF3 has known
   tweak-size weaknesses — so FF1 is the single vetted primitive (see README).

## Testing

```sh
cargo test --workspace --all-features    # pure unit + arrow-boundary harness + integration
cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --all -- --check
make test-sql                            # builds release, sets VGI_MASK_WORKER, haybarn over test/sql/*
make test                                # cargo test + sql
```

CI (`.github/workflows/ci.yml`) runs fmt/clippy/build/test plus a gated
`e2e-sql` job (installs `uv` + `haybarn-unittest`, runs `make test-sql`).

## Function surface

Scalars (positional-only): `mask_fpe` (VARCHAR), `mask_unfpe` (VARCHAR),
`mask_token` (VARCHAR), `mask_redact` (VARCHAR), `mask_version` (VARCHAR). 5 FPE
format profiles, 4 redaction modes.

## Security posture (do not overstate in docs)

FPE leaks on small domains; deterministic masking is frequency-analyzable on
low-cardinality columns; key management (HSM/KMS, rotation) is the real enterprise
concern and is **out of scope** — the worker just takes a key. README states all
of this prominently; keep it honest.
