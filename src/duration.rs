//! Parsing of human-friendly delays such as `14d`, `30m`, `1h30m`.

use std::time::Duration;

use anyhow::{bail, Result};
use sqlx::postgres::types::PgInterval;

/// Parses a delay made of one or more `<number><unit>` groups.
///
/// Units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks).
/// Groups may be concatenated (`1h30m`, `1d12h`) or separated by spaces.
/// A bare number is refused: the unit is mandatory to avoid ambiguity.
pub fn parse_duration(input: &str) -> Result<Duration> {
    let s = input.trim();
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
    Ok(Duration::from_secs(total))
}

/// Converts a delay to a PostgreSQL `interval` (days + microseconds, no months).
pub fn to_pg_interval(d: Duration) -> PgInterval {
    let secs = d.as_secs();
    let days = i32::try_from(secs / 86_400).unwrap_or(i32::MAX);
    let micros = i64::try_from((secs % 86_400) * 1_000_000).unwrap_or(i64::MAX);
    PgInterval {
        months: 0,
        days,
        microseconds: micros,
    }
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
        for bad in ["", "14", "d", "14x", "1h30", "abc", "-5m", "1.5h"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn converts_to_pg_interval() {
        let iv = to_pg_interval(Duration::from_secs(2 * 86_400 + 90));
        assert_eq!(iv.months, 0);
        assert_eq!(iv.days, 2);
        assert_eq!(iv.microseconds, 90_000_000);
    }
}
