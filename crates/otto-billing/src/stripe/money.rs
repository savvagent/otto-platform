//! Exact conversion from platform money to Stripe's decimal strings.

use super::error::StripeError;

/// Millionths of a cent per cent.
const UCENTS_PER_CENT: i64 = 1_000_000;

/// Convert a unit price in millionths of a cent to Stripe's
/// `unit_amount_decimal`, which is in cents with up to 12 decimal places.
///
/// Exact: integer division and remainder, never floats. The result has no
/// trailing zeros and at most 6 decimal places. Negative prices are refused.
///
/// ```
/// use otto_billing::stripe::ucents_to_unit_amount_decimal as conv;
///
/// assert_eq!(conv(0).unwrap(), "0");
/// assert_eq!(conv(1).unwrap(), "0.000001");      // a millionth of a cent
/// assert_eq!(conv(1_500_000).unwrap(), "1.5");    // a cent and a half
/// assert_eq!(conv(250_000_000).unwrap(), "250");  // $2.50
/// assert!(conv(-1).is_err());
/// ```
pub fn ucents_to_unit_amount_decimal(ucents: i64) -> Result<String, StripeError> {
    if ucents < 0 {
        return Err(StripeError::InvalidRequest(format!(
            "unit price must not be negative (got {ucents} ucents)"
        )));
    }
    let whole = ucents / UCENTS_PER_CENT;
    let frac = ucents % UCENTS_PER_CENT;
    if frac == 0 {
        return Ok(whole.to_string());
    }
    let digits = format!("{frac:06}");
    Ok(format!("{whole}.{}", digits.trim_end_matches('0')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_conversions() {
        for (ucents, want) in [
            (0, "0"),
            (1, "0.000001"),
            (10, "0.00001"),
            (100_000, "0.1"),
            (999_999, "0.999999"),
            (1_000_000, "1"),
            (1_000_001, "1.000001"),
            (1_500_000, "1.5"),
            (123_456_789, "123.456789"),
            (i64::MAX, "9223372036854.775807"),
        ] {
            assert_eq!(
                ucents_to_unit_amount_decimal(ucents).unwrap(),
                want,
                "{ucents}"
            );
        }
    }

    /// Parse the decimal back to ucents and check it round-trips, over a
    /// spread of values including every remainder width.
    #[test]
    fn round_trips() {
        fn back(s: &str) -> i64 {
            let (w, f) = s.split_once('.').unwrap_or((s, ""));
            assert!(f.len() <= 6 && !f.ends_with('0'));
            let f = format!("{f:0<6}");
            w.parse::<i64>().unwrap() * UCENTS_PER_CENT + f.parse::<i64>().unwrap()
        }
        let mut v: i64 = 1;
        while v < i64::MAX / 7 {
            for x in [v, v + 1, v - 1, v * 3 + 7] {
                assert_eq!(back(&ucents_to_unit_amount_decimal(x).unwrap()), x);
            }
            v *= 7;
        }
    }

    #[test]
    fn negative_is_refused() {
        assert!(ucents_to_unit_amount_decimal(-1).is_err());
        assert!(ucents_to_unit_amount_decimal(i64::MIN).is_err());
    }
}
