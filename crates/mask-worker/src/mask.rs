//! The pure masking engine — no Arrow, no RPC. Everything here is deterministic
//! and unit-tested directly.
//!
//! Three families of transform:
//!
//! 1. **Format-preserving encryption (FPE)** — [`fpe_encrypt`] / [`fpe_decrypt`],
//!    built on NIST SP 800-38G **FF1** (the `fpe` crate, AES-256 round function).
//!    A [`Format`] profile decides *which characters* of the input are
//!    encryptable and over *what radix*, leaving structural characters
//!    (separators, the email domain, etc.) in place so the output keeps the input
//!    shape. The same key round-trips: `fpe_decrypt(fpe_encrypt(x)) == x`.
//!
//! 2. **Deterministic tokenization** — [`token`]. An HMAC-SHA-256 pseudonym:
//!    same input + key ⇒ same token, so it preserves referential integrity for
//!    cross-table joins. Not reversible.
//!
//! 3. **Partial redaction** — [`redact`]. Irreversible masking that keeps a hint
//!    (e.g. the last four characters) and stars the rest.
//!
//! ## Key handling
//!
//! Callers pass an arbitrary key *string*. We derive a fixed 256-bit AES key with
//! `SHA-256(key_string)` (and a separate HMAC key for tokenization). This means
//! any non-empty string is a usable key; serious deployments should source the
//! key from a secret manager / KMS rather than a SQL literal (see the README).
//!
//! ## The FF1 minimum-domain rule (small-domain policy)
//!
//! FF1 refuses to operate unless the domain `radix^len >= 1_000_000` (NIST's
//! minimum to make the permutation non-trivial). For radix 10 that means at least
//! **6** encryptable digits; for radix 36, at least **4**. When the encryptable
//! run in a value is *too short* for its radix, we **pass the value through
//! unchanged** rather than weakly encrypt it or panic. This is a deliberate,
//! documented policy: FPE on a tiny domain leaks anyway (see README caveats).
//! Such pass-through values still round-trip (decrypt is also a no-op on them).

use aes::Aes256;
use fpe::ff1::{FlexibleNumeralString, FF1};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// NIST FF1 minimum domain size: the function refuses `radix^len < 1_000_000`.
const MIN_DOMAIN: u128 = 1_000_000;

/// Errors the engine can return. The Arrow layer decides how each maps to a
/// DuckDB NULL / error / pass-through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskError {
    /// The key string was empty — refused, since an empty key is almost
    /// certainly a mistake and would silently give everyone the same "secret".
    EmptyKey,
    /// An unknown `format` profile name was supplied.
    UnknownFormat(String),
    /// An unknown `redact` mode name was supplied.
    UnknownMode(String),
    /// The internal FF1 primitive reported an error (should not happen for
    /// inputs that pass our pre-checks; surfaced for completeness).
    Fpe(String),
}

impl std::fmt::Display for MaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaskError::EmptyKey => write!(f, "mask key must be a non-empty string"),
            MaskError::UnknownFormat(s) => write!(
                f,
                "unknown mask format '{s}' (expected one of: digits, alnum, card, ssn, email)"
            ),
            MaskError::UnknownMode(s) => write!(
                f,
                "unknown redact mode '{s}' (expected one of: last4, first4, email, all)"
            ),
            MaskError::Fpe(e) => write!(f, "format-preserving encryption failed: {e}"),
        }
    }
}

impl std::error::Error for MaskError {}

/// Derive the 256-bit AES key for FF1 from the caller's key string.
fn aes_key(key: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vgi-mask:fpe:v1"); // domain separation from the HMAC token key
    h.update(key.as_bytes());
    h.finalize().into()
}

/// A character alphabet for FF1: a contiguous-or-listed set of symbols with a
/// stable index in `[0, radix)`. Characters not in the alphabet are *structural*
/// and pass through unchanged at their position.
struct Alphabet {
    /// Ordered symbols; index in this slice is the FF1 numeral value.
    symbols: &'static [char],
}

impl Alphabet {
    fn radix(&self) -> u32 {
        self.symbols.len() as u32
    }

    /// Numeral value of `c`, or `None` if `c` is structural (not encryptable).
    fn value_of(&self, c: char) -> Option<u16> {
        self.symbols.iter().position(|&s| s == c).map(|i| i as u16)
    }

    fn symbol_of(&self, v: u16) -> char {
        self.symbols[v as usize]
    }
}

const DIGITS: Alphabet = Alphabet {
    symbols: &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'],
};

// Radix-62, case-preserving: digits, then lowercase, then uppercase.
const ALNUM: Alphabet = Alphabet {
    symbols: &[
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    ],
};

/// The minimum encryptable-run length FF1 will accept for a given radix
/// (smallest `len` with `radix^len >= 1_000_000`).
fn min_len_for_radix(radix: u32) -> usize {
    let mut domain: u128 = 1;
    let mut len = 0usize;
    while domain < MIN_DOMAIN {
        domain = domain.saturating_mul(radix as u128);
        len += 1;
    }
    len
}

/// Encrypt the numeral sequence `nums` (each in `[0, radix)`) in place, returning
/// a new vector. `forward = true` encrypts, `false` decrypts. The caller has
/// already guaranteed `nums.len() >= min_len_for_radix(radix)`.
fn ff1_apply(key: &str, radix: u32, nums: Vec<u16>, forward: bool) -> Result<Vec<u16>, MaskError> {
    let ff =
        FF1::<Aes256>::new(&aes_key(key), radix).map_err(|e| MaskError::Fpe(format!("{e:?}")))?;
    let ns = FlexibleNumeralString::from(nums);
    let out = if forward {
        ff.encrypt(&[], &ns)
    } else {
        ff.decrypt(&[], &ns)
    }
    .map_err(|e| MaskError::Fpe(format!("{e:?}")))?;
    Ok(Vec::<u16>::from(out))
}

/// Encrypt (or decrypt) every encryptable character of `value` over `alphabet`,
/// leaving structural characters in place. Round-trips with the same key.
///
/// If the encryptable run is shorter than FF1's minimum domain, the value is
/// returned unchanged (small-domain pass-through; see module docs).
fn fpe_over_alphabet(
    key: &str,
    value: &str,
    alphabet: &Alphabet,
    forward: bool,
) -> Result<String, MaskError> {
    let chars: Vec<char> = value.chars().collect();
    // Collect the numeral values of the encryptable positions, remembering where
    // they sit so we can splice the result back in.
    let mut positions = Vec::new();
    let mut nums = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        if let Some(v) = alphabet.value_of(c) {
            positions.push(i);
            nums.push(v);
        }
    }
    if nums.len() < min_len_for_radix(alphabet.radix()) {
        // Too few encryptable characters to satisfy FF1 — pass through unchanged.
        return Ok(value.to_string());
    }
    let transformed = ff1_apply(key, alphabet.radix(), nums, forward)?;
    let mut out = chars;
    for (slot, &pos) in positions.iter().enumerate() {
        out[pos] = alphabet.symbol_of(transformed[slot]);
    }
    Ok(out.into_iter().collect())
}

/// A format profile that preserves a particular shape under FPE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Encrypt every `[0-9]` digit (radix 10); all other characters pass through.
    Digits,
    /// Encrypt every `[0-9A-Za-z]` character (radix 62, case-preserving).
    Alnum,
    /// 16-digit payment card: encrypt the first 15 digits, then fix the 16th to
    /// the Luhn check digit so the output is a Luhn-valid 16-digit number.
    Card,
    /// Encrypt the 9 SSN digits (radix 10), preserving any `-` separators.
    Ssn,
    /// Encrypt the local part (before the last `@`) over the alnum alphabet,
    /// preserving the `@domain` exactly so the address still routes-shaped.
    Email,
}

impl Format {
    /// Parse a profile name (case-insensitive).
    pub fn parse(name: &str) -> Result<Format, MaskError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "digits" | "digit" => Ok(Format::Digits),
            "alnum" | "alphanumeric" => Ok(Format::Alnum),
            "card" | "pan" | "ccn" => Ok(Format::Card),
            "ssn" => Ok(Format::Ssn),
            "email" | "mail" => Ok(Format::Email),
            other => Err(MaskError::UnknownFormat(other.to_string())),
        }
    }
}

/// The Luhn checksum of a slice of digit values (0–9), used by the card profile.
/// Returns the check digit that makes the whole number Luhn-valid when appended.
fn luhn_check_digit(payload: &[u16]) -> u16 {
    // `payload` are the leading digits; the check digit will be the rightmost, so
    // doubling starts at the check digit's left neighbour (an "odd" position from
    // the right of the full number).
    let mut sum = 0u32;
    let mut double = true;
    for &d in payload.iter().rev() {
        let mut v = d as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    ((10 - (sum % 10)) % 10) as u16
}

/// Format-preserving encrypt `value` under `format` and `key`.
pub fn fpe_encrypt(value: &str, format: Format, key: &str) -> Result<String, MaskError> {
    if key.is_empty() {
        return Err(MaskError::EmptyKey);
    }
    fpe_dispatch(value, format, key, true)
}

/// Inverse of [`fpe_encrypt`]; round-trips with the same key and format.
pub fn fpe_decrypt(value: &str, format: Format, key: &str) -> Result<String, MaskError> {
    if key.is_empty() {
        return Err(MaskError::EmptyKey);
    }
    fpe_dispatch(value, format, key, false)
}

fn fpe_dispatch(
    value: &str,
    format: Format,
    key: &str,
    forward: bool,
) -> Result<String, MaskError> {
    match format {
        Format::Digits => fpe_over_alphabet(key, value, &DIGITS, forward),
        Format::Alnum => fpe_over_alphabet(key, value, &ALNUM, forward),
        Format::Ssn => fpe_over_alphabet(key, value, &DIGITS, forward),
        Format::Email => fpe_email(key, value, forward),
        Format::Card => fpe_card(key, value, forward),
    }
}

/// Email: preserve `@domain`, FPE the local part over the alnum alphabet.
fn fpe_email(key: &str, value: &str, forward: bool) -> Result<String, MaskError> {
    match value.rsplit_once('@') {
        Some((local, domain)) if !domain.is_empty() => {
            let enc_local = fpe_over_alphabet(key, local, &ALNUM, forward)?;
            Ok(format!("{enc_local}@{domain}"))
        }
        // No usable domain → treat the whole thing as an alnum value.
        _ => fpe_over_alphabet(key, value, &ALNUM, forward),
    }
}

/// Card: a 16-digit PAN stays 16 digits and Luhn-valid. We FPE the first 15
/// digits and recompute the 16th as their Luhn check digit. Decryption FPE-inverts
/// the first 15 and likewise recomputes the check digit, so it round-trips.
///
/// Inputs that are not exactly 16 digits (after stripping non-digits) fall back to
/// the plain `digits` profile so we never panic or mangle unexpected shapes.
fn fpe_card(key: &str, value: &str, forward: bool) -> Result<String, MaskError> {
    let digit_positions: Vec<usize> = value
        .char_indices()
        .filter(|(_, c)| c.is_ascii_digit())
        .map(|(i, _)| i)
        .collect();
    if digit_positions.len() != 16 {
        // Not a 16-digit PAN — fall back to plain digit FPE (still shape-preserving).
        return fpe_over_alphabet(key, value, &DIGITS, forward);
    }
    let bytes = value.as_bytes();
    let nums: Vec<u16> = digit_positions
        .iter()
        .map(|&i| (bytes[i] - b'0') as u16)
        .collect();
    // FPE only the first 15 digits; the 16th is derived.
    let head = nums[..15].to_vec();
    let transformed = ff1_apply(key, DIGITS.radix(), head, forward)?;
    let check = luhn_check_digit(&transformed);
    let mut new_digits = transformed;
    new_digits.push(check);
    // Splice the 16 new digits back over the original digit positions.
    let mut out: Vec<char> = value.chars().collect();
    for (slot, &i_byte) in digit_positions.iter().enumerate() {
        // map byte offset back to char index (all digits are ASCII, 1 byte each)
        let ci = value[..i_byte].chars().count();
        out[ci] = DIGITS.symbol_of(new_digits[slot]);
    }
    Ok(out.into_iter().collect())
}

/// Deterministic pseudonym: lowercase hex of `HMAC-SHA-256(key, value)`, truncated
/// to 32 hex chars (128 bits). Same input + key ⇒ same token, so joins survive.
/// Not reversible.
pub fn token(value: &str, key: &str) -> Result<String, MaskError> {
    if key.is_empty() {
        return Err(MaskError::EmptyKey);
    }
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(format!("vgi-mask:token:v1:{key}").as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    let tag = mac.finalize().into_bytes();
    Ok(hex::encode(&tag[..16]))
}

/// Irreversible partial redaction modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactMode {
    /// Keep the last 4 characters, star the rest: `1234567890` → `******7890`.
    Last4,
    /// Keep the first 4 characters, star the rest: `1234567890` → `1234******`.
    First4,
    /// Email: keep first char of local + the domain: `alice@x.com` → `a****@x.com`.
    Email,
    /// Replace every character with `*`.
    All,
}

impl RedactMode {
    pub fn parse(name: &str) -> Result<RedactMode, MaskError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "last4" => Ok(RedactMode::Last4),
            "first4" => Ok(RedactMode::First4),
            "email" => Ok(RedactMode::Email),
            "all" | "full" => Ok(RedactMode::All),
            other => Err(MaskError::UnknownMode(other.to_string())),
        }
    }
}

/// Apply an irreversible redaction `mode` to `value`. Non-`*` structural
/// characters (spaces, dashes) inside a kept region are preserved; in the starred
/// region each character (including separators) becomes `*` so nothing leaks.
pub fn redact(value: &str, mode: RedactMode) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    match mode {
        RedactMode::All => "*".repeat(n),
        RedactMode::Last4 => {
            let keep = 4.min(n);
            let mut s: String = "*".repeat(n - keep);
            s.extend(chars[n - keep..].iter());
            s
        }
        RedactMode::First4 => {
            let keep = 4.min(n);
            let mut s: String = chars[..keep].iter().collect();
            s.push_str(&"*".repeat(n - keep));
            s
        }
        RedactMode::Email => match value.rsplit_once('@') {
            Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
                let first = local.chars().next().unwrap();
                let stars = "*".repeat(local.chars().count().saturating_sub(1));
                format!("{first}{stars}@{domain}")
            }
            _ => "*".repeat(n),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "correct horse battery staple";

    #[test]
    fn min_len_table() {
        assert_eq!(min_len_for_radix(10), 6); // 10^6 = 1_000_000
        assert_eq!(min_len_for_radix(62), 4); // 62^4 ≈ 14.7M
    }

    // ---- round-trip for every format ----

    fn roundtrip(value: &str, fmt: Format) {
        let enc = fpe_encrypt(value, fmt, KEY).unwrap();
        let dec = fpe_decrypt(&enc, fmt, KEY).unwrap();
        assert_eq!(dec, value, "round-trip failed for {fmt:?} on {value:?}");
    }

    #[test]
    fn roundtrips_all_formats() {
        roundtrip("4012888888881881", Format::Card);
        roundtrip("123-45-6789", Format::Ssn);
        roundtrip("8675309123", Format::Digits);
        roundtrip("AKIA1234567890ABCDEF", Format::Alnum);
        roundtrip("alice.smith@example.com", Format::Email);
    }

    // ---- format preservation ----

    #[test]
    fn card_stays_16_digits_and_luhn_valid() {
        let enc = fpe_encrypt("4012888888881881", Format::Card, KEY).unwrap();
        assert_eq!(enc.len(), 16);
        assert!(enc.chars().all(|c| c.is_ascii_digit()));
        // Luhn check of the full 16-digit number must be 0.
        let nums: Vec<u16> = enc.chars().map(|c| c as u16 - '0' as u16).collect();
        // recompute: drop check digit, verify it matches
        let expect = luhn_check_digit(&nums[..15]);
        assert_eq!(expect, nums[15], "card output is not Luhn-valid");
    }

    #[test]
    fn ssn_keeps_dashes_and_shape() {
        let enc = fpe_encrypt("123-45-6789", Format::Ssn, KEY).unwrap();
        assert_eq!(enc.len(), 11);
        assert_eq!(&enc[3..4], "-");
        assert_eq!(&enc[6..7], "-");
        assert!(enc.chars().filter(|c| c.is_ascii_digit()).count() == 9);
    }

    #[test]
    fn email_preserves_domain() {
        let enc = fpe_encrypt("alice.smith@example.com", Format::Email, KEY).unwrap();
        assert!(
            enc.ends_with("@example.com"),
            "domain must be preserved: {enc}"
        );
        assert!(enc.contains('.'), "local-part separators preserved");
    }

    #[test]
    fn digits_keeps_length() {
        let enc = fpe_encrypt("8675309123", Format::Digits, KEY).unwrap();
        assert_eq!(enc.len(), 10);
        assert!(enc.chars().all(|c| c.is_ascii_digit()));
    }

    // ---- the value actually changes (not identity) ----

    #[test]
    fn encryption_changes_value() {
        let v = "4012888888881881";
        assert_ne!(fpe_encrypt(v, Format::Card, KEY).unwrap(), v);
        let s = "123-45-6789";
        assert_ne!(fpe_encrypt(s, Format::Ssn, KEY).unwrap(), s);
    }

    // ---- determinism + key sensitivity ----

    #[test]
    fn deterministic_same_key() {
        let a = fpe_encrypt("8675309123", Format::Digits, KEY).unwrap();
        let b = fpe_encrypt("8675309123", Format::Digits, KEY).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_differ() {
        let a = fpe_encrypt("8675309123", Format::Digits, "key-one").unwrap();
        let b = fpe_encrypt("8675309123", Format::Digits, "key-two").unwrap();
        assert_ne!(a, b, "different keys must give different ciphertext");
    }

    // ---- small-domain pass-through ----

    #[test]
    fn short_digit_run_passes_through() {
        // Only 3 digits < min 6 for radix 10 → unchanged, and still round-trips.
        let v = "12-3";
        let enc = fpe_encrypt(v, Format::Digits, KEY).unwrap();
        assert_eq!(enc, v);
        assert_eq!(fpe_decrypt(&enc, Format::Digits, KEY).unwrap(), v);
    }

    // ---- empty key refused ----

    #[test]
    fn empty_key_errors() {
        assert_eq!(
            fpe_encrypt("123456", Format::Digits, ""),
            Err(MaskError::EmptyKey)
        );
        assert_eq!(token("x", ""), Err(MaskError::EmptyKey));
    }

    // ---- tokenization ----

    #[test]
    fn token_is_deterministic_and_key_sensitive() {
        assert_eq!(
            token("acct-42", KEY).unwrap(),
            token("acct-42", KEY).unwrap()
        );
        assert_ne!(
            token("acct-42", KEY).unwrap(),
            token("acct-43", KEY).unwrap()
        );
        assert_ne!(
            token("acct-42", "k1").unwrap(),
            token("acct-42", "k2").unwrap()
        );
        assert_eq!(token("acct-42", KEY).unwrap().len(), 32);
    }

    // ---- redaction ----

    #[test]
    fn redact_modes() {
        assert_eq!(redact("1234567890", RedactMode::Last4), "******7890");
        assert_eq!(redact("1234567890", RedactMode::First4), "1234******");
        assert_eq!(redact("1234567890", RedactMode::All), "**********");
        assert_eq!(
            redact("alice@example.com", RedactMode::Email),
            "a****@example.com"
        );
        // short string: last4 keeps all of it
        assert_eq!(redact("ab", RedactMode::Last4), "ab");
    }

    #[test]
    fn parse_names() {
        assert_eq!(Format::parse("CARD").unwrap(), Format::Card);
        assert_eq!(Format::parse(" ssn ").unwrap(), Format::Ssn);
        assert!(Format::parse("bogus").is_err());
        assert_eq!(RedactMode::parse("LAST4").unwrap(), RedactMode::Last4);
        assert!(RedactMode::parse("bogus").is_err());
    }

    #[test]
    fn luhn_known_vector() {
        // 4012888888881881 is a known Luhn-valid test PAN.
        let nums: Vec<u16> = "401288888888188"
            .chars()
            .map(|c| c as u16 - '0' as u16)
            .collect();
        assert_eq!(luhn_check_digit(&nums), 1);
    }
}
