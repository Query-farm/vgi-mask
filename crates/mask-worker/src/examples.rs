//! Composed example queries: realistic SQL that combines two or more of the
//! worker's functions in one query (masked views, pseudonymous joins, encrypt +
//! verify). Each `(description, sql)` pair is defined once here and referenced
//! from both the schema-level `vgi.example_queries` list (`lib.rs`) and the
//! example list of the function that drives the query (`scalar/*.rs`), so the
//! two copies cannot drift. `test/sql/compose.test` executes every one of them.

/// A `(description, sql)` example pair.
pub type Example = (&'static str, &'static str);

/// mask_token + mask_redact + mask_fpe: one masked view of a customer table.
pub const MASKED_CUSTOMER_VIEW: Example = (
    "Build a masked view of a customer table in one query: a joinable token for the email \
     (mask_token), display-safe email and card hints (mask_redact), and a reversibly encrypted, \
     still SSN-shaped SSN (mask_fpe).",
    "SELECT c.id, mask.main.mask_token(c.email, 'my-secret-key') AS customer_key, mask.main.mask_redact(c.email, 'email') AS email_display, mask.main.mask_redact(c.card, 'last4') AS card_display, mask.main.mask_fpe(c.ssn, 'ssn', 'my-secret-key') AS ssn_protected FROM (VALUES (1, 'alice@example.com', '4012888888881881', '123-45-6789'), (2, 'bob@example.org', '5555555555554444', '987-65-4321')) AS c(id, email, card, ssn) ORDER BY c.id;",
);

/// mask_token (join key on both sides) + mask_redact (display): pseudonymous join.
pub const PSEUDONYMOUS_JOIN: Example = (
    "Join an orders extract that was shared with emails replaced by tokens back to the customer \
     table by tokenizing the customer emails with the same key, then total spend per customer \
     showing only the redacted email (alice 200, bob 65, carol 15).",
    "WITH customers(email, region) AS (VALUES ('alice@example.com', 'EU'), ('bob@example.org', 'US'), ('carol@example.net', 'US')), shared_orders AS (SELECT mask.main.mask_token(o.email, 'my-secret-key') AS customer_key, o.amount FROM (VALUES ('alice@example.com', 120), ('bob@example.org', 40), ('alice@example.com', 80), ('carol@example.net', 15), ('bob@example.org', 25)) AS o(email, amount)) SELECT mask.main.mask_redact(c.email, 'email') AS customer, c.region, SUM(s.amount) AS total_spend FROM customers AS c JOIN shared_orders AS s ON s.customer_key = mask.main.mask_token(c.email, 'my-secret-key') GROUP BY ALL ORDER BY total_spend DESC;",
);

/// mask_fpe + mask_unfpe over a column: encrypt, then prove every row decrypts.
pub const ENCRYPT_AND_VERIFY: Example = (
    "Format-preserving encrypt a column of card numbers and, in the same query, check that \
     mask_unfpe recovers every original under the same profile and key (round_trips is true on \
     every row).",
    "WITH enc AS (SELECT card, mask.main.mask_fpe(card, 'card', 'my-secret-key') AS encrypted FROM (VALUES ('4012888888881881'), ('5555555555554444'), ('4111111111111111')) AS cards(card)) SELECT card, encrypted, mask.main.mask_unfpe(encrypted, 'card', 'my-secret-key') = card AS round_trips FROM enc ORDER BY card;",
);

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Example; 3] = [MASKED_CUSTOMER_VIEW, PSEUDONYMOUS_JOIN, ENCRYPT_AND_VERIFY];
    const FUNCTIONS: [&str; 4] = ["mask_fpe(", "mask_unfpe(", "mask_token(", "mask_redact("];

    #[test]
    fn composed_examples_are_lint_shaped() {
        for (description, sql) in ALL {
            assert!(!description.is_empty());
            // One line (JSON tag + agent display), catalog-qualified (VGI505),
            // ordered (VGI510), and composing 2+ distinct worker functions.
            assert!(!sql.contains('\n'), "{sql}");
            assert!(sql.contains("ORDER BY"), "{sql}");
            assert!(!sql.contains("SELECT *"), "{sql}");
            let used: Vec<_> = FUNCTIONS
                .iter()
                .filter(|f| sql.contains(&format!("mask.main.{f}")))
                .collect();
            assert!(used.len() >= 2, "{sql} composes only {used:?}");
            for f in FUNCTIONS {
                assert_eq!(
                    sql.matches(f).count(),
                    sql.matches(&format!("mask.main.{f}")).count(),
                    "unqualified {f} in {sql}"
                );
            }
        }
    }
}
