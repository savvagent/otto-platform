//! Platform meter keys to Stripe meter event names.
//!
//! A meter key is `<service>/<meter>`, with
//! service `^[a-z][a-z0-9-]{0,62}$` and meter `^[a-z][a-z0-9_]{0,62}$`. The
//! event name uses only `[a-z0-9_]`, so `-` has to become `_`, and the mapping
//! has to stay injective even though meters already contain `_`.
//!
//! # Encoding
//!
//! A key is *plain* when the service has no `--` and does not end in `-`, and
//! the meter has no `__`. Nearly every real key is plain, and encodes as
//!
//! ```text
//! service with '-' -> '_'  ++  "__"  ++  meter          otto-factory/jobs_completed
//!                                                       -> otto_factory__jobs_completed
//! ```
//!
//! Any other key is *escaped*: every `-` in the service becomes `_h`, every
//! `_` in the meter becomes `_u`, and the halves are joined with `___`:
//!
//! ```text
//! a--b/x__y  ->  a_h_hb___x_u_uy
//! ```
//!
//! # Why this is injective
//!
//! Call a maximal run of two or more `_` a *long run*.
//!
//! - Plain: the service half has no `__` and does not end in `_` (it would
//!   only do so from a trailing `-`), and the meter half has no `__` and starts
//!   with a letter. So the name has exactly one long run, of length exactly 2,
//!   and it is the separator. Each half is recovered by splitting there; the
//!   service by mapping `_` back to `-` (a service has no `_` of its own), the
//!   meter as-is.
//! - Escaped: every `_` inside either half is immediately followed by `h` or
//!   `u`, so neither half contains `__`; the service half cannot end in `_`
//!   and the meter half starts with a letter. So the name has exactly one long
//!   run, of length exactly 3. Each half is recovered by splitting there and
//!   undoing a prefix-free substitution.
//!
//! The run length tells the two forms apart, and within each form decoding is
//! unique, so distinct keys give distinct names. [`parse_meter_event_name`]
//! is that decoder; the tests check it inverts [`meter_event_name`] over every
//! key up to length 4 on a small alphabet, and that no two of them collide.
//!
//! # Length
//!
//! Stripe caps a meter's `event_name` at [`MAX_EVENT_NAME_LEN`] (100)
//! characters, and [`meter_event_name`] refuses a key whose name would be
//! longer ([`EventNameError::TooLong`]) rather than truncating it, which
//! would break injectivity. Refusing part of the domain cannot create a
//! collision. In practice: a plain key fits when
//! `len(service) + len(meter) <= 98`; an escaped key counts every separator
//! twice and needs `len(service) + len(meter) + separators <= 97`. Meter
//! declarations should be held to that when they are registered.

/// A meter key part that does not match its pattern.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventNameError {
    #[error("service slug must match ^[a-z][a-z0-9-]{{0,62}}$")]
    InvalidService,
    #[error("meter name must match ^[a-z][a-z0-9_]{{0,62}}$")]
    InvalidMeter,
    #[error("meter key maps to a Stripe event name longer than {MAX_EVENT_NAME_LEN} characters")]
    TooLong,
}

/// The longest `event_name` Stripe accepts for a billing meter.
pub const MAX_EVENT_NAME_LEN: usize = 100;

/// Whether `name` could be a Stripe meter event name this module produces:
/// 1 to [`MAX_EVENT_NAME_LEN`] of `[a-z0-9_]`. A raw `service/meter` key fails.
pub(super) fn is_event_name_shaped(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_EVENT_NAME_LEN
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

const MAX_PART: usize = 63;

fn valid_part(s: &str, sep: u8) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_PART
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == sep)
}

fn valid_service(s: &str) -> bool {
    valid_part(s, b'-')
}

fn valid_meter(m: &str) -> bool {
    valid_part(m, b'_')
}

fn is_plain(service: &str, meter: &str) -> bool {
    !service.contains("--") && !service.ends_with('-') && !meter.contains("__")
}

/// The Stripe meter event name for the meter key `<service>/<meter>`.
///
/// Deterministic and injective over valid keys (see the module docs).
///
/// ```
/// use savvagent_billing::stripe::meter_event_name;
///
/// assert_eq!(
///     meter_event_name("otto-factory", "jobs_completed").unwrap(),
///     "otto_factory__jobs_completed"
/// );
/// assert_eq!(meter_event_name("a--b", "x__y").unwrap(), "a_h_hb___x_u_uy");
/// assert!(meter_event_name("Otto", "x").is_err());
/// ```
pub fn meter_event_name(service: &str, meter: &str) -> Result<String, EventNameError> {
    if !valid_service(service) {
        return Err(EventNameError::InvalidService);
    }
    if !valid_meter(meter) {
        return Err(EventNameError::InvalidMeter);
    }
    let name = if is_plain(service, meter) {
        format!("{}__{meter}", service.replace('-', "_"))
    } else {
        format!(
            "{}___{}",
            service.replace('-', "_h"),
            meter.replace('_', "_u")
        )
    };
    if name.len() > MAX_EVENT_NAME_LEN {
        return Err(EventNameError::TooLong);
    }
    Ok(name)
}

/// The inverse of [`meter_event_name`]: `(service, meter)` for a name it
/// produced, `None` for anything else (including non-canonical spellings).
///
/// ```
/// use savvagent_billing::stripe::parse_meter_event_name;
///
/// assert_eq!(
///     parse_meter_event_name("otto_factory__jobs_completed"),
///     Some(("otto-factory".into(), "jobs_completed".into()))
/// );
/// assert_eq!(parse_meter_event_name("no_separator"), None);
/// ```
pub fn parse_meter_event_name(name: &str) -> Option<(String, String)> {
    // Locate the single long run of '_'.
    let b = name.as_bytes();
    let mut run: Option<(usize, usize)> = None;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'_' {
            let start = i;
            while i < b.len() && b[i] == b'_' {
                i += 1;
            }
            if i - start >= 2 {
                if run.is_some() {
                    return None;
                }
                run = Some((start, i - start));
            }
        } else {
            i += 1;
        }
    }
    let (start, len) = run?;
    let (left, right) = (&name[..start], &name[start + len..]);
    let (service, meter) = match len {
        2 => (left.replace('_', "-"), right.to_owned()),
        3 => (unescape(left, 'h', '-')?, unescape(right, 'u', '_')?),
        _ => return None,
    };
    // Canonical check: only names this module would produce decode.
    (meter_event_name(&service, &meter).ok()? == name).then_some((service, meter))
}

/// Undo `c -> "_" + tag`. Any `_` not followed by `tag` is invalid.
fn unescape(s: &str, tag: char, c: char) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '_' {
            if chars.next()? != tag {
                return None;
            }
            out.push(c);
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Every string over `alphabet` of length 1..=max starting with `a`/`b`.
    fn all(alphabet: &[char], max: usize) -> Vec<String> {
        let mut out: Vec<String> = vec!["a".into(), "b".into()];
        let mut frontier = out.clone();
        for _ in 1..max {
            let next: Vec<String> = frontier
                .iter()
                .flat_map(|p| alphabet.iter().map(move |c| format!("{p}{c}")))
                .collect();
            out.extend(next.iter().cloned());
            frontier = next;
        }
        out
    }

    #[test]
    fn example_from_the_story() {
        assert_eq!(
            meter_event_name("otto-factory", "jobs_completed").unwrap(),
            "otto_factory__jobs_completed"
        );
    }

    #[test]
    fn collisions_a_naive_mapping_would_have_are_distinct() {
        // A naive `s.replace('-', '_') + "__" + m` maps all of these to "a__b__c".
        let names = [
            meter_event_name("a", "b__c").unwrap(),
            meter_event_name("a--b", "c").unwrap(),
            meter_event_name("a-", "b__c").unwrap(),
        ];
        assert_eq!(names[0], "a___b_u_uc");
        assert_eq!(names[1], "a_h_hb___c");
        assert_eq!(names[2], "a_h___b_u_uc");
        // ...and "a-"/"_b" style trailing-separator keys stay apart too.
        assert_ne!(
            meter_event_name("a-", "b").unwrap(),
            meter_event_name("a", "b").unwrap()
        );
    }

    /// Exhaustive over every key whose parts are up to 4 characters from an
    /// alphabet containing a letter, a digit and the separator: no two keys
    /// share a name, every name is `[a-z0-9_]`, and parsing inverts encoding.
    #[test]
    fn injective_and_invertible_exhaustively() {
        let services = all(&['a', '0', '-'], 4);
        let meters = all(&['a', '0', '_'], 4);
        let mut seen: HashMap<String, (String, String)> = HashMap::new();
        for s in &services {
            for m in &meters {
                let name = meter_event_name(s, m).unwrap();
                assert!(
                    name.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'),
                    "{name}"
                );
                assert_eq!(
                    parse_meter_event_name(&name),
                    Some((s.clone(), m.clone())),
                    "{s}/{m} -> {name}"
                );
                if let Some(prev) = seen.insert(name.clone(), (s.clone(), m.clone())) {
                    panic!("{prev:?} and {s}/{m} both map to {name}");
                }
            }
        }
        assert_eq!(seen.len(), services.len() * meters.len());
    }

    #[test]
    fn length_cap_plain() {
        // 49 + "__" + 49 = 100: accepted, and it round-trips.
        let (s, m) = ("a".repeat(49), "b".repeat(49));
        let name = meter_event_name(&s, &m).unwrap();
        assert_eq!(name.len(), 100);
        assert_eq!(parse_meter_event_name(&name), Some((s.clone(), m)));
        // One more character: 101, refused.
        assert_eq!(
            meter_event_name(&s, &"b".repeat(50)),
            Err(EventNameError::TooLong)
        );
    }

    #[test]
    fn length_cap_escaped() {
        // 33 'a' + trailing '-' -> 35 escaped, + "___" + 62 = 100.
        let s = format!("{}-", "a".repeat(33));
        let m = "b".repeat(62);
        let name = meter_event_name(&s, &m).unwrap();
        assert_eq!(name.len(), 100);
        assert_eq!(parse_meter_event_name(&name), Some((s.clone(), m)));
        assert_eq!(
            meter_event_name(&s, &"b".repeat(63)),
            Err(EventNameError::TooLong)
        );
        // Valid parts at their maximum length are refused, not truncated.
        let s = format!("a{}", "-".repeat(62));
        let m = format!("a{}", "_".repeat(62));
        assert_eq!(meter_event_name(&s, &m), Err(EventNameError::TooLong));
        // An over-long name never parses either.
        let long = format!("{}__{}", "a".repeat(49), "b".repeat(50));
        assert_eq!(parse_meter_event_name(&long), None);
    }

    #[test]
    fn event_name_shape() {
        assert!(is_event_name_shaped("otto_factory__jobs_completed"));
        assert!(is_event_name_shaped(&"a".repeat(100)));
        assert!(!is_event_name_shaped(&"a".repeat(101)));
        assert!(!is_event_name_shaped(""));
        assert!(!is_event_name_shaped("otto-factory/jobs_completed"));
        assert!(!is_event_name_shaped("Jobs"));
    }

    #[test]
    fn invalid_parts_are_refused() {
        for s in ["", "A", "1a", "-a", "a_b", "a/b", "a.b", &"a".repeat(64)] {
            assert_eq!(
                meter_event_name(s, "m"),
                Err(EventNameError::InvalidService),
                "{s}"
            );
        }
        for m in ["", "A", "1a", "_a", "a-b", "a/b", &"a".repeat(64)] {
            assert_eq!(
                meter_event_name("s", m),
                Err(EventNameError::InvalidMeter),
                "{m}"
            );
        }
    }

    #[test]
    fn non_canonical_names_do_not_parse() {
        for n in [
            "",
            "a",
            "a_b",
            "a____b",
            "a__b__c",
            "a___b___c",
            // Escaped form for a key that is plain: not canonical.
            "a_hb___c",
            // Bad escapes.
            "a_xb___c",
            "a___b_xc",
            // Trailing separator in the service half of a plain name.
            "a___",
            "__a",
            "A__b",
        ] {
            assert_eq!(parse_meter_event_name(n), None, "{n}");
        }
    }
}
