//! Parsing of `KEY=VALUE` profile settings into the jsonb object expected by
//! `pass_policy.create_profile()` / `alter_profile()`.

use anyhow::{bail, Result};
use serde_json::{Map, Value};

/// Converts one `KEY=VALUE` item.  Booleans and integers are typed, `null`
/// becomes JSON null (clears an optional setting such as `max_age`), anything
/// else stays a string (intervals such as `"30 days"`).  The keywords
/// (`true`/`false`, `on`/`off`, `yes`/`no`, `null`) are case-insensitive, as
/// in PostgreSQL (`TRUE`, `Off`, `NULL`).  A string is passed unchanged.
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
    let json = match value.to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" => Value::Bool(true),
        "false" | "off" | "no" => Value::Bool(false),
        "null" => Value::Null,
        _ => match value.parse::<i64>() {
            Ok(n) => Value::from(n),
            Err(_) => Value::String(value.to_string()),
        },
    };
    Ok((key.to_string(), json))
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
