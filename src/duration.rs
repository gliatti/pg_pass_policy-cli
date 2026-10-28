//! Parsing of human-friendly delays such as `14d`, `30m`, `1h30m`.

use std::time::Duration;

use anyhow::{bail, Result};
use sqlx::postgres::types::PgInterval;

/// Upper bound of a delay: 100 years (36500 days).  Larger values have no
/// use for a lock or a search window, and `now() + delay` must stay a valid
/// PostgreSQL timestamp.
pub const MAX_DURATION_SECS: u64 = 36_500 * 86_400;

/// Parses a delay made of one or more `<number><unit>` groups.
///
/// Units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks).
/// Groups may be concatenated (`1h30m`, `1d12h`) or separated by spaces.
/// A bare number is refused: the unit is mandatory to avoid ambiguity.
/// The total must be positive (`0s` is refused) and is bounded by
/// [`MAX_DURATION_SECS`] (100 years).
pub fn parse_duration(input: &str) -> Result<Duration> {
    match parse_total(input, input)? {
        Some(d) => Ok(d),
        None => bail!("invalid duration \"{input}\": must be greater than zero"),
    }
}

/// Like [`parse_duration`], but a total of zero (`0`, `0s`, `0m0s`, `00`)
/// is accepted and returned as `None` (used for "no limit").  A bare
/// number is read as seconds; any other value follows the rules (units,
/// bounds, messages) of [`parse_duration`].
pub fn parse_duration_or_zero(input: &str) -> Result<Option<Duration>> {
    let t = input.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        return parse_total(&format!("{t}s"), input);
    }
    parse_total(input, input)
}

/// Sum of the `<number><unit>` groups of `text` (`None` when zero);
/// messages name `input`, the value given by the user.
fn parse_total(text: &str, input: &str) -> Result<Option<Duration>> {
    let s = text.trim();
    if s.is_empty() {
        bail!("empty duration");
    }
    let mut total: u64 = 0;
    let mut number = String::new();
    let mut seen_group = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            number.push(c);
            continue;
        }
        if c.is_whitespace() {
            if !number.is_empty() {
                bail!("invalid duration \"{input}\": unit expected after \"{number}\"");
            }
            continue;
        }
        if number.is_empty() {
            bail!("invalid duration \"{input}\": number expected before \"{c}\"");
        }
        let n: u64 = number
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid duration \"{input}\": number too large"))?;
        let secs = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3_600,
            'd' => 86_400,
            'w' => 7 * 86_400,
            _ => bail!("invalid duration \"{input}\": unknown unit \"{c}\" (use s, m, h, d or w)"),
        };
        total = n
            .checked_mul(secs)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(|| anyhow::anyhow!("invalid duration \"{input}\": overflow"))?;
        number.clear();
        seen_group = true;
    }
    if !number.is_empty() {
        bail!("invalid duration \"{input}\": unit missing (use s, m, h, d or w)");
    }
    if !seen_group {
        bail!("invalid duration \"{input}\"");
    }
    if total > MAX_DURATION_SECS {
        bail!("invalid duration \"{input}\": at most 36500d (100 years)");
    }
    Ok((total > 0).then(|| Duration::from_secs(total)))
}

/// Converts a delay to a PostgreSQL `interval` (days + microseconds, no
/// months).  A delay that does not fit is an error, never a silently
/// truncated value (`parse_duration` already bounds what the CLI accepts).
pub fn to_pg_interval(d: Duration) -> Result<PgInterval> {
    let secs = d.as_secs();
    let days = i32::try_from(secs / 86_400)
        .map_err(|_| anyhow::anyhow!("duration too large for a PostgreSQL interval"))?;
    // < 86400 s, always representable
    let micros = ((secs % 86_400) * 1_000_000 + u64::from(d.subsec_micros())) as i64;
    Ok(PgInterval {
        months: 0,
        days,
        microseconds: micros,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_units() {
        assert_eq!(
            parse_duration("14d").unwrap(),
            Duration::from_secs(14 * 86_400)
        );
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1_800));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7_200));
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(
            parse_duration("1w").unwrap(),
            Duration::from_secs(7 * 86_400)
        );
        assert_eq!(parse_duration(" 5M ").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn parses_compound_values() {
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5_400));
        assert_eq!(
            parse_duration("1d 12h").unwrap(),
            Duration::from_secs(129_600)
        );
    }

    #[test]
    fn rejects_invalid_values() {
        for bad in [
            "", "14", "d", "14x", "1h30", "abc", "-5m", "1.5h", "0s", "0d0h", "00m",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn zero_is_accepted_by_the_or_zero_variant() {
        for zero in ["0", "000", "0s", "0m0s", " 0h ", "00m", "0d 0h"] {
            assert_eq!(parse_duration_or_zero(zero).unwrap(), None, "{zero:?}");
        }
        assert_eq!(
            parse_duration_or_zero("45").unwrap(),
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            parse_duration_or_zero("1h30m").unwrap(),
            Some(Duration::from_secs(5_400))
        );
        for bad in ["", "-1", "5x", "1h30", "36501d", "99999999999999999999999"] {
            assert!(parse_duration_or_zero(bad).is_err(), "{bad:?}");
        }
        // the messages name the value given, not the internal "<n>s" form
        let err = parse_duration_or_zero("3153600001")
            .unwrap_err()
            .to_string();
        assert!(err.contains("\"3153600001\""), "{err}");
    }

    #[test]
    fn converts_to_pg_interval() {
        let iv = to_pg_interval(Duration::from_secs(2 * 86_400 + 90)).unwrap();
        assert_eq!(iv.months, 0);
        assert_eq!(iv.days, 2);
        assert_eq!(iv.microseconds, 90_000_000);
        let max = to_pg_interval(Duration::from_secs(MAX_DURATION_SECS)).unwrap();
        assert_eq!(max.days, 36_500);
        // out of range for an interval: error, not i32::MAX days
        let huge = Duration::from_secs((i32::MAX as u64 + 1) * 86_400);
        assert!(to_pg_interval(huge).is_err());
    }

    #[test]
    fn bounds_the_total() {
        assert_eq!(
            parse_duration("36500d").unwrap(),
            Duration::from_secs(MAX_DURATION_SECS)
        );
        assert_eq!(
            parse_duration("5214w2d").unwrap(),
            Duration::from_secs(MAX_DURATION_SECS)
        );
        for big in ["36500d1s", "36501d", "99999999999d", "5215w", "3000000000d"] {
            let err = parse_duration(big).unwrap_err();
            assert!(err.to_string().contains("100 years"), "{big}: {err}");
        }
        // overflow of u64 is still reported as such
        assert!(parse_duration("99999999999999999999d").is_err());
    }
}
