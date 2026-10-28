//! Rendering of query results as a text table or as JSON.

use std::fmt::Display;
use std::io::{IsTerminal, Write};

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

/// The standard output was closed by its reader (`pgpp audit | head -1`):
/// `EPIPE` on a write.  Rust ignores `SIGPIPE`, so that `println!` would
/// panic; the writes of this module return this error instead, which
/// [`crate::failure_code`] turns into a silent exit with code 0.
#[derive(Debug)]
pub struct BrokenPipe;

impl Display for BrokenPipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the standard output was closed (broken pipe)")
    }
}

impl std::error::Error for BrokenPipe {}

/// True when `err` (or one of its causes) is [`BrokenPipe`].
pub fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|c| c.is::<BrokenPipe>())
}

/// Writes `text` and a newline to the standard output, then flushes it so
/// that a closed pipe is detected here and not at exit.
pub fn write_line(text: impl Display) -> Result<()> {
    write_line_to(&mut std::io::stdout().lock(), text)
}

fn write_line_to(out: &mut impl Write, text: impl Display) -> Result<()> {
    writeln!(out, "{text}")
        .and_then(|()| out.flush())
        .map_err(map_stdout_error)
}

/// Error of a failed write to the standard output: [`BrokenPipe`] for
/// `EPIPE`, `cannot write to the standard output: ...` otherwise.  Shared
/// by every writer of stdout, buffered or not.
pub fn map_stdout_error(e: std::io::Error) -> anyhow::Error {
    if is_epipe(&e) {
        anyhow::Error::new(BrokenPipe)
    } else {
        anyhow::Error::new(e).context("cannot write to the standard output")
    }
}

/// True for the error of a write to a pipe whose reader is gone (`EPIPE`).
/// Shared by the writers of stdout ([`map_stdout_error`]) and of stderr
/// ([`write_stderr`]).
fn is_epipe(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::BrokenPipe
}

/// Writes `text` (and a newline when `newline`) to the standard error, then
/// flushes it.  `eprintln!` / `eprint!` panic when the write fails: a
/// standard error closed by its reader (`pgpp ... 2>&1 | head -1`) must not
/// turn a report into a panic.  A failure is ignored: the standard error is
/// where it would be reported.
pub fn write_stderr(text: impl Display, newline: bool) {
    let _ = write_stderr_to(&mut std::io::stderr().lock(), text, newline);
}

/// [`write_stderr`] on any writer: `Ok` for a closed pipe (`EPIPE`), the
/// other errors are returned (and ignored by [`write_stderr`]).
fn write_stderr_to(out: &mut impl Write, text: impl Display, newline: bool) -> std::io::Result<()> {
    let written = if newline {
        writeln!(out, "{text}")
    } else {
        write!(out, "{text}")
    };
    match written.and_then(|()| out.flush()) {
        Err(e) if is_epipe(&e) => Ok(()),
        other => other,
    }
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
    pub fn print(&self, fmt: Format, empty: &str) -> Result<()> {
        match fmt {
            Format::Json => write_line(self.to_json()),
            Format::Table => {
                if self.rows.is_empty() {
                    return write_line(empty);
                }
                let mut t = CTable::new();
                t.load_preset(UTF8_FULL_CONDENSED)
                    .set_content_arrangement(stdout_arrangement())
                    .set_header(&self.columns);
                for r in &self.rows {
                    t.add_row(r.iter().map(cell));
                }
                write_line(t)
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
pub fn print_record(record: &Map<String, Value>, fmt: Format) -> Result<()> {
    match fmt {
        Format::Json => write_line(Value::Object(record.clone())),
        Format::Table => {
            let mut t = CTable::new();
            t.load_preset(UTF8_FULL_CONDENSED)
                .set_content_arrangement(stdout_arrangement())
                .set_header(["setting", "value"]);
            for (k, v) in record {
                t.add_row([k.clone(), cell(v)]);
            }
            write_line(t)
        }
    }
}

/// Prints the outcome of an action: a sentence, or a JSON object.
pub fn print_message(fmt: Format, text: &str, json: Value) -> Result<()> {
    match fmt {
        Format::Json => write_line(json),
        Format::Table => write_line(text),
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

    /// A writer whose reader is gone, or that fails otherwise.
    struct Failing(std::io::ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(self.0.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_closed_pipe_is_reported_as_broken_pipe() {
        let err = write_line_to(&mut Failing(std::io::ErrorKind::BrokenPipe), "x").unwrap_err();
        assert!(is_broken_pipe(&err), "{err:#}");
        let err = write_line_to(&mut Failing(std::io::ErrorKind::Other), "x").unwrap_err();
        assert!(!is_broken_pipe(&err));
        assert!(format!("{err:#}").contains("cannot write to the standard output"));
        let err = map_stdout_error(std::io::ErrorKind::BrokenPipe.into());
        assert!(is_broken_pipe(&err));
        let err = map_stdout_error(std::io::ErrorKind::PermissionDenied.into());
        assert!(!is_broken_pipe(&err));
        assert!(format!("{err:#}").starts_with("cannot write to the standard output: "));
        let mut buf = Vec::new();
        write_line_to(&mut buf, json!({"a": 1})).unwrap();
        assert_eq!(buf, b"{\"a\":1}\n");
    }

    #[test]
    fn a_closed_stderr_does_not_panic() {
        // EPIPE is ignored, like a closed stdout; other errors are returned
        write_stderr_to(&mut Failing(std::io::ErrorKind::BrokenPipe), "x", true).unwrap();
        write_stderr_to(&mut Failing(std::io::ErrorKind::BrokenPipe), "x", false).unwrap();
        let err = write_stderr_to(&mut Failing(std::io::ErrorKind::Other), "x", true).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        let mut buf = Vec::new();
        write_stderr_to(&mut buf, "line", true).unwrap();
        write_stderr_to(&mut buf, "prompt: ", false).unwrap();
        assert_eq!(buf, b"line\nprompt: ");
    }

    #[test]
    fn cells_render_plainly() {
        assert_eq!(cell(&Value::Null), "");
        assert_eq!(cell(&json!("txt")), "txt");
        assert_eq!(cell(&json!(12)), "12");
        assert_eq!(cell(&json!({"k": 1})), "{\"k\":1}");
    }
}
