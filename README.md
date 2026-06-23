# vgi-mask

A [VGI](https://query.farm) worker that brings **format-preserving encryption**,
**deterministic tokenization**, and **partial redaction** of sensitive values to
DuckDB over Apache Arrow. The output **keeps the input's format**, so masked data
still looks like the real thing — a card number stays a Luhn-valid 16-digit
number, an SSN stays SSN-shaped, an email keeps its `@domain`.

```sql
LOAD vgi;
ATTACH 'mask' (TYPE vgi, LOCATION './target/release/mask-worker');
SET search_path = 'mask.main';

SELECT mask_fpe('4012888888881881', 'card', 'k');   -- e.g. 4263982640269299 (16-digit, Luhn-valid)
SELECT mask_fpe('123-45-6789', 'ssn', 'k');          -- e.g. 481-92-0573 (SSN-shaped)
SELECT mask_fpe('alice@corp.com', 'email', 'k');     -- e.g. x7qf2@corp.com (domain preserved)

SELECT mask_unfpe(mask_fpe('123-45-6789','ssn','k'), 'ssn', 'k');  -- 123-45-6789 (round-trips)

SELECT mask_token('customer-42', 'k');               -- stable pseudonym, joinable across tables
SELECT mask_redact('4111111111111111', 'last4');     -- ************1111
```

## Use cases

- **Safe non-prod datasets with referential integrity.** FPE and tokenization are
  *deterministic*: the same input always maps to the same output under a key, so
  foreign keys and joins still line up across tables in a masked copy.
- **GDPR / CCPA pseudonymization.** Replace direct identifiers with reversible
  (FPE) or irreversible (token / redact) pseudonyms while preserving shape so
  downstream schemas and validators keep working.
- **Reversible tokenization for joinable analytics.** Encrypt once, analyze on the
  masked values, decrypt with the key when you have the authority to.

## Function surface

All functions are **scalars** with **positional-only** arguments (VGI scalars do
not support `name := value`; that is table-only).

| Function | Signature | Notes |
| --- | --- | --- |
| `mask_fpe` | `mask_fpe(value VARCHAR, format VARCHAR, key VARCHAR) -> VARCHAR` | Format-preserving encrypt. `format` ∈ {`card`,`ssn`,`digits`,`alnum`,`email`} |
| `mask_unfpe` | `mask_unfpe(value VARCHAR, format VARCHAR, key VARCHAR) -> VARCHAR` | Inverse of `mask_fpe`; round-trips under the same key + format |
| `mask_token` | `mask_token(value VARCHAR, key VARCHAR) -> VARCHAR` | Deterministic HMAC-SHA-256 pseudonym (32 hex chars). Joinable, not reversible |
| `mask_redact` | `mask_redact(value VARCHAR, mode VARCHAR) -> VARCHAR` | Irreversible. `mode` ∈ {`last4`,`first4`,`email`,`all`} |
| `mask_version` | `mask_version() -> VARCHAR` | Worker version |

### Format profiles (`mask_fpe` / `mask_unfpe`)

| `format` | Preserves | What is encrypted |
| --- | --- | --- |
| `card` | 16 digits, **Luhn-valid** | First 15 digits FPE'd; 16th recomputed as the Luhn check digit |
| `ssn` | `NNN-NN-NNNN` shape (dashes kept) | The 9 digits |
| `digits` | length, all `[0-9]`; other chars in place | every `[0-9]` digit (radix 10) |
| `alnum` | length, case, `[0-9A-Za-z]`; other chars in place | every alphanumeric (radix 62) |
| `email` | the `@domain` exactly | the local part (before the last `@`), over the alnum alphabet |

### Redaction modes (`mask_redact`)

| `mode` | `1234567890` → | `alice@example.com` → |
| --- | --- | --- |
| `last4` | `******7890` | (stars all but last 4) |
| `first4` | `1234******` | |
| `email` | (stars all) | `a****@example.com` |
| `all` | `**********` | `*****************` |

## How the FPE works

`mask_fpe` is built on **NIST SP 800-38G FF1**, the standard format-preserving
encryption mode, via the well-vetted [`fpe`](https://crates.io/crates/fpe) crate
with **AES-256** as the round function. A format profile decides *which
characters* of the value are encryptable and over what radix; structural
characters (the dashes in an SSN, the `@domain` of an email) pass through
unchanged at their position. Because FF1 is a deterministic keyed permutation over
the chosen alphabet, the output is the same length and shape, and decryption with
the same key recovers the original exactly.

The caller's `key` string is stretched to a 256-bit AES key with SHA-256 (with
domain separation from the tokenization key). Any non-empty string works as a key;
an empty key is refused.

`mask_token` is a separate, non-reversible HMAC-SHA-256 pseudonym — use it when
you never need to decrypt but still want stable, joinable identifiers.

## NULL and error policy

- **NULL input** → **NULL** output (missing data flows through; a masked column of
  a nullable source stays nullable).
- **Unknown `format` / `mode`** → DuckDB **ERROR**. The caller named a profile that
  does not exist — a query bug, not dirty data — so it fails loudly.
- **Empty `key`** → DuckDB **ERROR** (an empty key would make every secret the same).
- **Value too short to encrypt** under its profile → **passed through unchanged**
  (see caveats). Such values still round-trip.

## ⚠️ Honest caveats — read before relying on this

Format-preserving encryption and deterministic masking trade some security for
shape preservation and joinability. Know exactly what you are getting:

1. **FPE on a SMALL domain leaks.** FF1 is a permutation over the value's domain.
   If that domain is tiny (e.g. a 3-digit field, or a status code with 5 possible
   values), the ciphertext space is just as tiny and an attacker who can encrypt
   chosen values, or who knows the value distribution, can recover the mapping.
   NIST FF1 itself refuses any domain below 1,000,000 (`radix^len < 1e6`); we honor
   that by **passing short values through unchanged** rather than weakly encrypting
   them. **Use FPE only on genuinely high-cardinality fields** (full card numbers,
   SSNs, account numbers), never on low-cardinality categoricals.

2. **Deterministic mode is vulnerable to frequency analysis.** Because the same
   input always maps to the same output (which is exactly what makes it joinable),
   an attacker who knows the *frequency distribution* of the plaintext can match it
   to the ciphertext distribution. On a low-cardinality column (sex, blood type,
   country, a boolean-ish field) this effectively de-anonymizes it. Determinism is
   appropriate for **high-cardinality identifiers used as join keys**, not for
   analytic attribute columns where you care about confidentiality of the value
   itself. If you do not need joinability, prefer non-deterministic encryption or
   `mask_redact`.

3. **Key management is the real enterprise concern, and is out of scope here.**
   This worker takes a key as a function argument (or, in a deployment, from a
   secret provider). That is fine for a demo or a tightly controlled batch job, but
   a serious deployment must not pass keys as SQL literals: they end up in query
   logs, query history, and `EXPLAIN` output. Production use wants the key sourced
   from an **HSM or a cloud KMS** (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp
   Vault), with rotation and access control — that is the runtime/operational
   upsell and is deliberately **not** implemented in the worker.

4. **FF3-1 is not included.** Only **FF1** is provided. The `fpe` crate ships a
   vetted FF1 but no FF3-1, and FF3 has known weaknesses for certain tweak sizes —
   so rather than pull in an unvetted FF3-1 implementation, this worker ships FF1
   as the single, well-reviewed primitive.

5. **`mask_token` is not reversible.** It is an HMAC, not encryption. There is no
   `untoken`. Use `mask_fpe` if you need to get the value back.

## Cryptography & licensing

All cryptographic primitives come from well-vetted, permissively licensed crates —
**no GPL/AGPL**:

| Crate | Purpose | License |
| --- | --- | --- |
| [`fpe`](https://crates.io/crates/fpe) | NIST FF1 format-preserving encryption | MIT OR Apache-2.0 |
| [`aes`](https://crates.io/crates/aes) | AES-256 block cipher (FF1 round function) | MIT OR Apache-2.0 |
| [`sha2`](https://crates.io/crates/sha2) | SHA-256 key derivation | MIT OR Apache-2.0 |
| [`hmac`](https://crates.io/crates/hmac) | HMAC-SHA-256 tokenization | MIT OR Apache-2.0 |
| [`hex`](https://crates.io/crates/hex) | token hex encoding | MIT OR Apache-2.0 |

The worker itself is **MIT** licensed — see [LICENSE](LICENSE).

## Development

```sh
make test       # cargo unit/integration tests + SQL E2E
make test-unit  # cargo test --workspace
make test-sql   # build release worker + DuckDB sqllogictest suite (haybarn-unittest)
make lint       # clippy (deny warnings) + rustfmt --check
make fmt        # rustfmt the workspace
```

The SQL E2E suite uses [`haybarn-unittest`](https://query.farm)
(`uv tool install haybarn-unittest`).
