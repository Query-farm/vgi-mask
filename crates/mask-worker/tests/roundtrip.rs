//! Integration tests for the pure masking engine. These exercise `mask-worker`'s
//! public API the same way the Arrow adapters do, but without any Arrow/RPC
//! plumbing: round-trip correctness, format preservation, determinism, and key
//! sensitivity.

use mask_worker::mask::{self, Format, RedactMode};

const KEY: &str = "integration-test-key";

fn is_luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = d;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}

#[test]
fn every_format_roundtrips() {
    for (val, fmt) in [
        ("4012888888881881", Format::Card),
        ("5555555555554444", Format::Card),
        ("123-45-6789", Format::Ssn),
        ("078051120", Format::Ssn),
        ("8675309123", Format::Digits),
        ("AKIAIOSFODNN7EXAMPLE", Format::Alnum),
        ("john.doe@corp.example.com", Format::Email),
    ] {
        let enc = mask::fpe_encrypt(val, fmt, KEY).unwrap();
        let dec = mask::fpe_decrypt(&enc, fmt, KEY).unwrap();
        assert_eq!(dec, val, "round-trip failed: {fmt:?} {val}");
    }
}

#[test]
fn card_output_is_16_digits_and_luhn_valid() {
    let enc = mask::fpe_encrypt("4012888888881881", Format::Card, KEY).unwrap();
    assert_eq!(enc.chars().filter(|c| c.is_ascii_digit()).count(), 16);
    assert!(is_luhn_valid(&enc), "card output must be Luhn-valid: {enc}");
}

#[test]
fn email_keeps_domain() {
    let enc = mask::fpe_encrypt("john.doe@corp.example.com", Format::Email, KEY).unwrap();
    assert!(enc.ends_with("@corp.example.com"));
    assert_ne!(enc, "john.doe@corp.example.com");
}

#[test]
fn deterministic_and_key_sensitive() {
    let a = mask::fpe_encrypt("8675309123", Format::Digits, KEY).unwrap();
    let b = mask::fpe_encrypt("8675309123", Format::Digits, KEY).unwrap();
    assert_eq!(a, b, "same input+key must be deterministic");
    let c = mask::fpe_encrypt("8675309123", Format::Digits, "a-different-key").unwrap();
    assert_ne!(a, c, "different keys must differ");
}

#[test]
fn token_preserves_join_keys() {
    // Same value tokenizes identically (joinable), different values do not.
    assert_eq!(
        mask::token("customer-77", KEY).unwrap(),
        mask::token("customer-77", KEY).unwrap()
    );
    assert_ne!(
        mask::token("customer-77", KEY).unwrap(),
        mask::token("customer-78", KEY).unwrap()
    );
}

#[test]
fn redact_is_irreversible_and_shaped() {
    assert_eq!(
        mask::redact("4111111111111111", RedactMode::Last4),
        "************1111"
    );
    assert_eq!(
        mask::redact("alice@example.com", RedactMode::Email),
        "a****@example.com"
    );
}
