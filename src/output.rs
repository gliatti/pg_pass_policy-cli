//! Rendering of query results as a text table or as JSON.

use std::io::IsTerminal;

use anyhow::{bail, Result};
use clap::ValueEnum;
use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table as CTable};
use serde_json::{Map, Value};
use sqlx::postgres::types::Oid;
use sqlx::postgres::PgRow;
use sqlx::{Column, Row, TypeInfo};

/// Output format, selectable with `-f/--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable table
    Table,
    /// JSON (array of objects, or one object)
    Json,
}

/// A result set: column names plus rows of JSON values.
#[derive(Debug, Default)]
pub struct ResultSet {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
}

impl ResultSet {
    /// Decodes rows returned by PostgreSQL.  Only text, integer, boolean and
    /// json(b) columns are supported: SQL queries cast other types
    /// (timestamps, intervals, inet, ...) to text.
    pub fn from_rows(rows: &[PgRow]) -> Result<Self> {
        let mut rs = ResultSet::default();
        let Some(first) = rows.first() else {
            return Ok(rs);
        };
        rs.columns = first
            .columns()
            .iter()
            .map(|c| c.name().to_string())
            .collect();
        for row in rows {
            let mut out = Vec::with_capacity(rs.columns.len());
            for (i, col) in row.columns().iter().enumerate() {
                let v = match col.type_info().name() {
                    "TEXT" | "VARCHAR" | "NAME" | "BPCHAR" => {
                        row.try_get::<Option<String>, _>(i)?.map(Value::from)
                    }
                    "INT2" => row.try_get::<Option<i16>, _>(i)?.map(Value::from),
                    "INT4" => row.try_get::<Option<i32>, _>(i)?.map(Value::from),
                    "INT8" => row.try_get::<Option<i64>, _>(i)?.map(Value::from),
                    "OID" => row.try_get::<Option<Oid>, _>(i)?.map(|o| Value::from(o.0)),
                    "FLOAT4" => row.try_get::<Option<f32>, _>(i)?.map(Value::from),
                    "FLOAT8" => row.try_get::<Option<f64>, _>(i)?.map(Value::from),
                    "BOOL" => row.try_get::<Option<bool>, _>(i)?.map(Value::from),
                    "JSON" | "JSONB" => row.try_get::<Option<Value>, _>(i)?,
                    other => bail!(
                        "internal error: unsupported column type {other} for \"{}\"",
                        col.name()
                    ),
                };
                out.push(v.unwrap_or(Value::Null));
            }
            rs.rows.push(out);
        }
        Ok(rs)
    }

    /// One row as a JSON object.
    fn record(&self, row: &[Value]) -> Map<String, Value> {
        self.columns
            .iter()
            .cloned()
            .zip(row.iter().cloned())
            .collect()
    }

    /// Rows as JSON objects.
    pub fn to_json(&self) -> Value {
        Value::Array(
            self.rows
                .iter()
                .map(|r| Value::Object(self.record(r)))
                .collect(),
        )
    }

    /// First row as a JSON object, if any.
    pub fn first_record(&self) -> Option<Map<String, Value>> {
        self.rows.first().map(|r| self.record(r))
    }

    /// Prints the result set in the requested format.  `empty` is the text
    /// shown by the table format when there is no row.
    pub fn print(&self, fmt: Format, empty: &str) {
        match fmt {
            Format::Json => println!("{}", self.to_json()),
            Format::Table => {
                if self.rows.is_empty() {
                    println!("{empty}");
                    return;
                }
                let mut t = CTable::new();
                t.load_preset(UTF8_FULL_CONDENSED)
                    .set_content_arrangement(stdout_arrangement())
                    .set_header(&self.columns);
                for r in &self.rows {
                    t.add_row(r.iter().map(cell));
                }
                println!("{t}");
            }
        }
    }
}

/// Layout of the tables printed on stdout: wrapped to the terminal width on
/// a terminal, never wrapped otherwise (pipe, file), so that a value
/// (timestamp, reason) is not split over several lines for a script.
fn stdout_arrangement() -> ContentArrangement {
    arrangement(std::io::stdout().is_terminal())
}

fn arrangement(is_terminal: bool) -> ContentArrangement {
    if is_terminal {
        ContentArrangement::Dynamic
    } else {
        ContentArrangement::Disabled
    }
}

/// Text shown in a table cell for a JSON value.
pub fn cell(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Prints one record (JSON object) as a key/value table or as JSON.
pub fn print_record(record: &Map<String, Value>, fmt: Format) {
    match fmt {
        Format::Json => println!("{}", Value::Object(record.clone())),
        Format::Table => {
            let mut t = CTable::new();
            t.load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(stdout_arrangement())
                .set_header(["setting", "value"]);
            for (k, v) in record {
                t.add_row([k.clone(), cell(v)]);
            }
            println!("{t}");
        }
    }
}

/// Prints the outcome of an action: a sentence, or a JSON object.
pub fn print_message(fmt: Format, text: &str, json: Value) {
    match fmt {
        Format::Json => println!("{json}"),
        Format::Table => println!("{text}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_output_zips_columns_and_rows() {
        let rs = ResultSet {
            columns: vec!["a".into(), "b".into()],
            rows: vec![vec![json!(1), Value::Null], vec![json!("x"), json!(true)]],
        };
        assert_eq!(
            rs.to_json(),
            json!([{"a": 1, "b": null}, {"a": "x", "b": true}])
        );
        assert_eq!(
            Value::Object(rs.first_record().unwrap()),
            json!({"a": 1, "b": null})
        );
        assert!(ResultSet::default().first_record().is_none());
    }

    #[test]
    fn tables_wrap_only_on_a_terminal() {
        assert!(matches!(arrangement(true), ContentArrangement::Dynamic));
        assert!(matches!(arrangement(false), ContentArrangement::Disabled));
        // a long value is kept on one line when wrapping is disabled
        let long = "x".repeat(300);
        let mut t = CTable::new();
        t.load_preset(UTF8_FULL_CONDENSED)
            .set_content_arrangement(arrangement(false))
            .set_width(40)
            .set_header(["k", "v"])
            .add_row(["a", long.as_str()]);
        assert!(t.to_string().lines().any(|l| l.contains(&long)));
        t.set_content_arrangement(arrangement(true));
        assert!(!t.to_string().lines().any(|l| l.contains(&long)));
    }

    #[test]
    fn cells_render_plainly() {
        assert_eq!(cell(&Value::Null), "");
        assert_eq!(cell(&json!("txt")), "txt");
        assert_eq!(cell(&json!(12)), "12");
        assert_eq!(cell(&json!({"k": 1})), "{\"k\":1}");
    }
}
