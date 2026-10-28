//! Parsing of `KEY=VALUE` profile settings into the jsonb object expected by
//! `pass_policy.create_profile()` / `alter_profile()`.

use anyhow::{bail, Result};
use serde_json::{Map, Value};

/// Converts one `KEY=VALUE` item.  Booleans and integers are typed (an
/// integer in canonical decimal form only: `16`, `-1`; `+16`, `016` or
/// `-0` stay strings), `null`
/// becomes JSON null (clears an optional setting such as `max_age`), anything
/// else stays a string (intervals such as `"30 days"`).  The keywords
/// (`true`/`false`, `on`/`off`, `yes`/`no`, `null`) are case-insensitive, as
/// in PostgreSQL (`TRUE`, `Off`, `NULL`).  A string is passed unchanged.
///
/// A value between double quotes is always a string, without the quotes:
/// `max_age="90"` sends the string `"90"` where `max_age=90` sends the
/// number 90, and `"null"` / `"true"` stay strings.  Inside the quotes,
/// `\"` gives a literal double quote and `\\` a literal backslash (so that
/// a value may end with one: `"a\\"`); every other character, inner blanks,
/// a bare `"` and any other backslash included, is kept as is.
pub fn parse_kv(item: &str) -> Result<(String, Value)> {
    let Some((key, value)) = item.split_once('=') else {
        bail!("invalid setting \"{item}\": expected KEY=VALUE");
    };
    let key = key.trim();
    if key.is_empty()
        || !key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        bail!("invalid setting key \"{key}\": expected a lower-case profile column name");
    }
    let value = value.trim();
    if let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        return Ok((key.to_string(), Value::String(unescape_quoted(inner))));
    }
    let json = match value.to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" => Value::Bool(true),
        "false" | "off" | "no" => Value::Bool(false),
        "null" => Value::Null,
        // only the canonical decimal form is a number: `+5`, `007` or `-0`
        // (accepted by `i64::from_str`) stay strings, sent as typed
        _ => match value.parse::<i64>() {
            Ok(n) if n.to_string() == value => Value::from(n),
            _ => Value::String(value.to_string()),
        },
    };
    Ok((key.to_string(), json))
}

/// Content of a quoted value: `\"` becomes `"`, `\\` becomes `\`, anything
/// else is copied unchanged.
fn unescape_quoted(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                if next == '"' || next == '\\' {
                    out.push(next);
                    chars.next();
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

/// Builds the JSON object from already parsed `--set` items; a repeated key
/// is an error.
pub fn parse_settings(items: &[(String, Value)]) -> Result<Map<String, Value>> {
    let mut map = Map::new();
    for (k, v) in items {
        if map.insert(k.clone(), v.clone()).is_some() {
            bail!("setting \"{k}\" given twice");
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn types_values() {
        assert_eq!(
            parse_kv("min_length=16").unwrap(),
            ("min_length".into(), json!(16))
        );
        assert_eq!(
            parse_kv("reject_username=false").unwrap(),
            ("reject_username".into(), json!(false))
        );
        assert_eq!(
            parse_kv("max_age=null").unwrap(),
            ("max_age".into(), Value::Null)
        );
        assert_eq!(
            parse_kv("max_age=30 days").unwrap(),
            ("max_age".into(), json!("30 days"))
        );
        assert_eq!(
            parse_kv(" lock_duration = 1 hour ").unwrap(),
            ("lock_duration".into(), json!("1 hour"))
        );
    }

    #[test]
    fn keywords_are_case_insensitive() {
        for (item, expected) in [
            ("reject_username=TRUE", json!(true)),
            ("reject_username=True", json!(true)),
            ("reject_username=ON", json!(true)),
            ("reject_username=Yes", json!(true)),
            ("reject_username=FALSE", json!(false)),
            ("reject_username=Off", json!(false)),
            ("reject_username=NO", json!(false)),
            ("max_age=NULL", Value::Null),
            ("max_age=Null", Value::Null),
            // other strings keep their case
            ("max_age=30 Days", json!("30 Days")),
            ("max_age=nullx", json!("nullx")),
        ] {
            assert_eq!(parse_kv(item).unwrap().1, expected, "{item}");
        }
    }

    #[test]
    fn a_quoted_value_is_always_a_string() {
        for (item, expected) in [
            ("max_age=\"90\"", json!("90")),
            ("max_age = \"90\" ", json!("90")),
            ("reject_username=\"true\"", json!("true")),
            ("max_age=\"null\"", json!("null")),
            ("max_age=\" 30 days \"", json!(" 30 days ")),
            ("max_age=\"\"", json!("")),
            // a bare inner quote is kept
            ("max_age=\"a\"b\"", json!("a\"b")),
            // \" and \\ are escapes inside the quotes
            (r#"max_age="a\"b""#, json!("a\"b")),
            (r#"max_age="\"quoted\"""#, json!("\"quoted\"")),
            (r#"max_age="a\\""#, json!("a\\")),
            (r#"max_age="a\\\"b""#, json!("a\\\"b")),
            // any other backslash is kept, and so is a trailing lone one
            (r#"max_age="a\nb""#, json!("a\\nb")),
            (r#"max_age="a\""#, json!("a\\")),
            // no escape processing outside quotes
            (r#"max_age=a\"b"#, json!("a\\\"b")),
            // a lone or unbalanced quote is an ordinary string
            ("max_age=\"", json!("\"")),
            ("max_age=\"90", json!("\"90")),
            ("max_age=90\"", json!("90\"")),
        ] {
            assert_eq!(parse_kv(item).unwrap().1, expected, "{item}");
        }
        assert_eq!(parse_kv("max_age=90").unwrap().1, json!(90));
    }

    #[test]
    fn only_canonical_integers_are_numbers() {
        for (item, expected) in [
            ("min_length=16", json!(16)),
            ("min_length=0", json!(0)),
            ("min_length=-1", json!(-1)),
            ("min_length=9223372036854775807", json!(i64::MAX)),
            // accepted by i64::from_str, but not in canonical form
            ("min_length=+16", json!("+16")),
            ("min_length=016", json!("016")),
            ("min_length=00", json!("00")),
            ("min_length=-016", json!("-016")),
            ("min_length=-0", json!("-0")),
            ("min_length=+0", json!("+0")),
            // out of range
            (
                "min_length=9223372036854775808",
                json!("9223372036854775808"),
            ),
        ] {
            assert_eq!(parse_kv(item).unwrap().1, expected, "{item}");
        }
    }

    #[test]
    fn rejects_bad_items() {
        assert!(parse_kv("min_length").is_err());
        assert!(parse_kv("=5").is_err());
        assert!(parse_kv("Min-Length=5").is_err());
        assert!(parse_kv("a;drop=5").is_err());
    }

    #[test]
    fn builds_object_and_refuses_duplicates() {
        let items = [
            parse_kv("min_length=16").unwrap(),
            parse_kv("max_failures=3").unwrap(),
        ];
        let m = parse_settings(&items).unwrap();
        assert_eq!(
            Value::Object(m),
            json!({"min_length": 16, "max_failures": 3})
        );
        let dup = [
            parse_kv("min_length=16").unwrap(),
            parse_kv("min_length=20").unwrap(),
        ];
        assert!(parse_settings(&dup).is_err());
    }
}
