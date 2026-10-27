//! HashiCorp Vault KV v2 integration.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::header::HeaderValue;
use reqwest::{Certificate, StatusCode, Url};
use serde_json::{json, Value};

/// Where a secret is written: `POST {addr}/v1/{mount}/data/{path}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultTarget {
    pub mount: String,
    pub path: String,
}

impl VaultTarget {
    /// Splits `--vault-kv` into mount and path.  Without `--vault-mount`, the
    /// first path component is the mount (`secret/db/app` → `secret`, `db/app`).
    /// Every segment is validated so that the URL built from it cannot point
    /// to another endpoint than the one the operator typed.
    pub fn parse(kv_path: &str, mount: Option<&str>) -> Result<Self> {
        let kv_path = kv_path.trim().trim_matches('/');
        if kv_path.is_empty() {
            bail!("--vault-kv: empty path");
        }
        let (mount, path) = match mount {
            Some(m) => (m.trim().trim_matches('/').to_string(), kv_path.to_string()),
            None => match kv_path.split_once('/') {
                Some((m, p)) if !p.trim_matches('/').is_empty() => {
                    (m.to_string(), p.trim_matches('/').to_string())
                }
                _ => bail!(
                    "--vault-kv \"{kv_path}\": expected <mount>/<path> (or use --vault-mount)"
                ),
            },
        };
        if mount.is_empty() {
            bail!("--vault-mount: empty mount");
        }
        for seg in mount.split('/') {
            check_segment(seg, "--vault-mount")?;
        }
        for seg in path.split('/') {
            check_segment(seg, "--vault-kv")?;
        }
        Ok(VaultTarget { mount, path })
    }

    /// Vault path of the KV v2 data endpoint (`{mount}/data/{path}`), as
    /// used by policies and by `sys/capabilities-self`.
    pub fn api_path(&self) -> String {
        format!("{}/data/{}", self.mount, self.path)
    }

    /// URL of the KV v2 data endpoint, below the path of `addr` (if any).
    pub fn url(&self, addr: &Url) -> Url {
        let segments = std::iter::once("v1")
            .chain(self.mount.split('/'))
            .chain(std::iter::once("data"))
            .chain(self.path.split('/'));
        endpoint(addr, segments)
    }
}

/// Appends path segments to the base address.  Each segment is
/// percent-encoded by `url` as a single segment, so that it can never add a
/// query, a fragment or a `..` step; a trailing `/` of the base is dropped.
fn endpoint<'a>(addr: &Url, segments: impl IntoIterator<Item = &'a str>) -> Url {
    let mut url = addr.clone();
    url.path_segments_mut()
        .expect("check_addr only accepts http(s) URLs, which have a path")
        .pop_if_empty()
        .extend(segments);
    url
}

/// Refuses a path segment that would change the endpoint once placed in the
/// URL: empty, `.` or `..` (resolved by URL parsers, percent-encoding does not
/// help), or containing a character that starts a query, a fragment or a
/// percent escape, a backslash, whitespace or a control character.
fn check_segment(seg: &str, option: &str) -> Result<()> {
    if seg.is_empty() || seg == "." || seg == ".." {
        bail!("{option}: invalid path segment {seg:?}");
    }
    if seg
        .chars()
        .any(|c| matches!(c, '?' | '#' | '%' | '\\') || c.is_whitespace() || c.is_control())
    {
        bail!("{option}: invalid path segment {seg:?} (reserved character)");
    }
    Ok(())
}

/// Connection parameters, from `VAULT_ADDR`, `VAULT_TOKEN`, the optional
/// `VAULT_NAMESPACE` and the optional `VAULT_CACERT` / `VAULT_CAPATH`.
/// `Debug` is implemented by hand so that the token is never printed.
#[derive(Clone)]
pub struct VaultConfig {
    /// Validated `VAULT_ADDR`.
    pub addr: Url,
    /// `VAULT_TOKEN`, already validated as an HTTP header value (marked
    /// sensitive).
    token: HeaderValue,
    namespace: Option<HeaderValue>,
    /// HTTP client built once (with the extra root certificates) and used
    /// for every request: token preflight and secret write.
    client: reqwest::Client,
}

impl VaultConfig {
    /// Builds a configuration; `addr` must use `https://`, or `http://` on a
    /// loopback host only.
    pub fn new(
        addr: impl AsRef<str>,
        token: impl Into<String>,
        namespace: Option<String>,
    ) -> Result<Self> {
        Self::with_root_certs(addr, token, namespace, &[])
    }

    /// Same as [`VaultConfig::new`], trusting in addition `root_certs`
    /// (private CA) besides the system and webpki stores.
    pub fn with_root_certs(
        addr: impl AsRef<str>,
        token: impl Into<String>,
        namespace: Option<String>,
        root_certs: &[Certificate],
    ) -> Result<Self> {
        let addr = check_addr(addr.as_ref())?;
        let mut token = header_value(&token.into(), "VAULT_TOKEN")?;
        token.set_sensitive(true);
        let namespace = namespace
            .map(|ns| header_value(&ns, "VAULT_NAMESPACE"))
            .transpose()?;
        Ok(VaultConfig {
            addr,
            token,
            namespace,
            client: build_client(root_certs)?,
        })
    }

    /// Reads the environment and validates everything (address, token,
    /// certificates, HTTP client) so that a misconfiguration is reported
    /// before any password is rotated.  Surrounding whitespace (a final
    /// newline copied from a token file, for instance) is removed.
    pub fn from_env() -> Result<Self> {
        let addr = env_var("VAULT_ADDR").context("VAULT_ADDR is not set")?;
        let token = env_var("VAULT_TOKEN").context("VAULT_TOKEN is not set")?;
        let certs = root_certs_from_env()?;
        Self::with_root_certs(addr, token, env_var("VAULT_NAMESPACE"), &certs)
    }

    /// Request carrying the token and namespace headers.
    fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .request(method, url)
            .header("X-Vault-Token", self.token.clone())
            .header("X-Vault-Request", "true");
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns.clone());
        }
        req
    }
}

impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("addr", &self.addr.as_str())
            .field("token", &"<redacted>")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

/// Non-empty value of an environment variable, without surrounding
/// whitespace.
fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Validates a value sent as an HTTP header: visible ASCII only, as Vault
/// tokens and namespaces are (`HeaderValue` alone would accept a tab or
/// non-ASCII bytes).  The value itself is never put in the error message (it
/// may be the token).
fn header_value(value: &str, name: &str) -> Result<HeaderValue> {
    if value.is_empty() {
        bail!("{name} is empty");
    }
    let invalid = || {
        anyhow::anyhow!(
            "{name} contains a character that is not allowed in an HTTP header \
             (space, control character such as a newline, or non-ASCII character)"
        )
    };
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid());
    }
    HeaderValue::from_str(value).map_err(|_| invalid())
}

/// HTTP client trusting the system roots, the webpki roots and `root_certs`.
/// Certificate verification is never disabled.  Redirects are never
/// followed: a 307/308 would replay the token and the password to whatever
/// host the `Location` header names, bypassing the loopback rule of
/// `check_addr`.  A redirect is reported as an error instead.
fn build_client(root_certs: &[Certificate]) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none());
    for cert in root_certs {
        builder = builder.add_root_certificate(cert.clone());
    }
    builder.build().context("cannot build the HTTP client")
}

/// Checks `VAULT_ADDR` and returns it parsed: a URL whose scheme is `https`,
/// or `http` when the host is loopback (`127.0.0.0/8`, `::1`, `localhost`),
/// without query string, fragment or credentials.  Plain HTTP to a remote
/// host would send the token and the password in clear; a query or a
/// fragment would be carried over to (or truncate) every endpoint URL.
pub fn check_addr(addr: &str) -> Result<Url> {
    // The value is never echoed in the messages: it may hold credentials
    // (`user:pw@`) that are only detected once the URL is parsed.
    let url = Url::parse(addr).context("VAULT_ADDR is not a valid URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("VAULT_ADDR: credentials in the URL are not allowed (use VAULT_TOKEN)");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("VAULT_ADDR: a query string (?) or a fragment (#) is not allowed");
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" => {
            let host = url.host_str().unwrap_or("");
            let bare = host.trim_start_matches('[').trim_end_matches(']');
            let local = bare.eq_ignore_ascii_case("localhost")
                || bare
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
            if local {
                Ok(url)
            } else {
                bail!(
                    "VAULT_ADDR: plain http:// is only accepted for a loopback host \
                     (127.0.0.0/8, ::1, localhost); use https:// (set VAULT_CACERT or \
                     VAULT_CAPATH for a private CA)"
                )
            }
        }
        other => bail!("VAULT_ADDR: unsupported scheme {other:?} (use https://)"),
    }
}

/// Extra root certificates: `VAULT_CACERT` (one PEM file, possibly a bundle)
/// takes precedence over `VAULT_CAPATH` (a directory of `*.pem` / `*.crt`
/// files), as in the official Vault client.
fn root_certs_from_env() -> Result<Vec<Certificate>> {
    if let Some(file) = env_var("VAULT_CACERT") {
        return load_pem_bundle(Path::new(&file)).with_context(|| format!("VAULT_CACERT {file:?}"));
    }
    if let Some(dir) = env_var("VAULT_CAPATH") {
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("VAULT_CAPATH {dir:?}: cannot read the directory"))?;
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.is_file()
                    && matches!(
                        p.extension().and_then(|e| e.to_str()),
                        Some("pem" | "crt" | "cer")
                    )
            })
            .collect();
        paths.sort();
        let mut certs = Vec::new();
        for p in &paths {
            certs.extend(
                load_pem_bundle(p).with_context(|| format!("VAULT_CAPATH: {}", p.display()))?,
            );
        }
        if certs.is_empty() {
            bail!("VAULT_CAPATH {dir:?}: no *.pem / *.crt certificate found");
        }
        return Ok(certs);
    }
    Ok(Vec::new())
}

/// Loads every certificate of a PEM file.
pub fn load_pem_bundle(path: &Path) -> Result<Vec<Certificate>> {
    let pem = std::fs::read(path).context("cannot read the file")?;
    let certs = Certificate::from_pem_bundle(&pem).context("not a PEM certificate bundle")?;
    if certs.is_empty() {
        bail!("no certificate found in the file");
    }
    Ok(certs)
}

/// Body of the KV v2 write: `{"data":{"username","password","rotated_at"}}`.
pub fn build_payload(username: &str, password: &str, rotated_at: &str) -> Value {
    json!({
        "data": {
            "username": username,
            "password": password,
            "rotated_at": rotated_at,
        }
    })
}

/// Checks, before any rotation, that Vault is reachable at `VAULT_ADDR`
/// (no redirect), that it accepts `VAULT_TOKEN` and that the token may write
/// the target, so that these failures are reported while the password is
/// still unchanged.  Two requests:
///
/// 1. `GET {addr}/v1/auth/token/lookup-self` (allowed by Vault's `default`
///    policy): a network error, a redirect, a 401 or any other non-2xx
///    status is an error.  A 403 is only a warning: a token created with
///    `-no-default-policy` cannot introspect itself but may still write.
///    The response body (token metadata) is not read.
/// 2. `POST {addr}/v1/sys/capabilities-self` with the KV v2 data path: an
///    error when the capabilities of the token on that path contain none of
///    `create`, `update`, `root`.  When this endpoint is itself denied (403)
///    or its answer cannot be read, a warning is returned and the write is
///    attempted after the rotation.
///
/// Returns the warnings, which the caller prints.
pub async fn preflight(cfg: &VaultConfig, target: &VaultTarget) -> Result<Vec<String>> {
    let mut warnings = Vec::new();

    let url = endpoint(&cfg.addr, ["v1", "auth", "token", "lookup-self"]);
    let resp = cfg
        .request(reqwest::Method::GET, url.clone())
        .send()
        .await
        .with_context(|| format!("Vault preflight request to {url} failed"))?;
    let status = resp.status();
    if status.is_redirection() {
        bail!(redirect_message(status, &url));
    }
    if status == StatusCode::FORBIDDEN {
        warnings.push(format!(
            "Vault denied {url} (HTTP 403): VAULT_TOKEN cannot introspect itself \
             (token without the default policy?); its validity is checked through \
             sys/capabilities-self only"
        ));
    } else if !status.is_success() {
        bail!(
            "Vault refused VAULT_TOKEN at {url}: HTTP {status}{} (expired or revoked token?)",
            error_body(resp).await
        );
    }

    let path = target.api_path();
    let url = endpoint(&cfg.addr, ["v1", "sys", "capabilities-self"]);
    let resp = cfg
        .request(reqwest::Method::POST, url.clone())
        .json(&json!({ "paths": [path] }))
        .send()
        .await
        .with_context(|| format!("Vault preflight request to {url} failed"))?;
    let status = resp.status();
    if status.is_redirection() {
        bail!(redirect_message(status, &url));
    }
    if status == StatusCode::FORBIDDEN {
        warnings.push(format!(
            "Vault denied {url} (HTTP 403): the write permission of VAULT_TOKEN on \
             \"{path}\" could not be checked before the rotation"
        ));
        return Ok(warnings);
    }
    if !status.is_success() {
        bail!(
            "Vault preflight request to {url} failed: HTTP {status}{}",
            error_body(resp).await
        );
    }
    let capabilities = resp
        .json::<Value>()
        .await
        .ok()
        .and_then(|body| capabilities_of(&body, &path));
    match capabilities {
        None => warnings.push(format!(
            "unexpected answer of {url}: the write permission of VAULT_TOKEN on \
             \"{path}\" could not be checked before the rotation"
        )),
        Some(caps)
            if !caps
                .iter()
                .any(|c| matches!(c.as_str(), "create" | "update" | "root")) =>
        {
            bail!(
                "VAULT_TOKEN may not write \"{path}\": its capabilities there are [{}] \
                 (create or update required)",
                caps.join(", ")
            );
        }
        Some(_) => {}
    }
    Ok(warnings)
}

/// Capabilities of the token on `path` in a `sys/capabilities-self` answer:
/// `data.<path>`, `<path>` or `capabilities` (all three are returned by
/// Vault for a single path, depending on the version).
fn capabilities_of(body: &Value, path: &str) -> Option<Vec<String>> {
    let list = [
        body.pointer("/data").and_then(|d| d.get(path)),
        body.get(path),
        body.get("capabilities"),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_array)?;
    list.iter()
        .map(|c| c.as_str().map(str::to_string))
        .collect()
}

fn redirect_message(status: StatusCode, url: &Url) -> String {
    format!(
        "Vault answered HTTP {status} (redirect) at {url}: redirects are not followed, \
         point VAULT_ADDR at the final Vault address"
    )
}

/// `": <body>"` of an error response (Vault puts its error list there), or
/// an empty string.
async fn error_body(resp: reqwest::Response) -> String {
    let body = resp.text().await.unwrap_or_default();
    let body = body.trim();
    if body.is_empty() {
        String::new()
    } else {
        format!(": {body}")
    }
}

/// Writes the payload.  Errors (network, HTTP status) are reported with the
/// status and the response body, which Vault fills with its own error list;
/// the payload itself is never included.
pub async fn write_secret(cfg: &VaultConfig, target: &VaultTarget, payload: &Value) -> Result<()> {
    let url = target.url(&cfg.addr);
    let resp = cfg
        .request(reqwest::Method::POST, url.clone())
        .json(payload)
        .send()
        .await
        .with_context(|| format!("Vault request to {url} failed"))?;
    let status = resp.status();
    if status.is_redirection() {
        bail!(redirect_message(status, &url));
    }
    if !status.is_success() {
        bail!(
            "Vault refused the write to {url}: HTTP {status}{}",
            error_body(resp).await
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_mount_and_path() {
        assert_eq!(
            VaultTarget::parse("secret/db/app", None).unwrap(),
            VaultTarget {
                mount: "secret".into(),
                path: "db/app".into()
            }
        );
        assert_eq!(
            VaultTarget::parse("/secret/app/", None).unwrap(),
            VaultTarget {
                mount: "secret".into(),
                path: "app".into()
            }
        );
        assert_eq!(
            VaultTarget::parse("db/app", Some("kv")).unwrap(),
            VaultTarget {
                mount: "kv".into(),
                path: "db/app".into()
            }
        );
        assert!(VaultTarget::parse("secret", None).is_err());
        assert!(VaultTarget::parse("secret/", None).is_err());
        assert!(VaultTarget::parse("", None).is_err());
        assert!(VaultTarget::parse("app", Some("")).is_err());
    }

    #[test]
    fn rejects_segments_that_change_the_endpoint() {
        for bad in [
            "secret/app?x=1",
            "secret/db/app#prod",
            "secret/../x",
            "secret/./x",
            "secret/a//b",
            "secret/a%2Fb",
            "secret/a b",
            "secret/a\\b",
            "secret/a\tb",
        ] {
            let err = VaultTarget::parse(bad, None).unwrap_err();
            assert!(
                err.to_string().contains("invalid path segment"),
                "{bad}: {err}"
            );
        }
        assert!(VaultTarget::parse("x", Some("..")).is_err());
        assert!(VaultTarget::parse("x", Some("kv?a")).is_err());
        assert!(VaultTarget::parse("team/kv/app", None).is_ok());
    }

    #[test]
    fn builds_url() {
        let t = VaultTarget::parse("secret/db/app", None).unwrap();
        for addr in ["https://vault:8200", "https://vault:8200/"] {
            assert_eq!(
                t.url(&check_addr(addr).unwrap()).as_str(),
                "https://vault:8200/v1/secret/data/db/app"
            );
        }
        // a path prefix of VAULT_ADDR (reverse proxy) is kept
        let t = VaultTarget::parse("db/app", Some("team/kv")).unwrap();
        assert_eq!(
            t.url(&check_addr("https://proxy.example.net/vault/").unwrap())
                .as_str(),
            "https://proxy.example.net/vault/v1/team/kv/data/db/app"
        );
        assert_eq!(
            endpoint(
                &check_addr("http://127.0.0.1:8200").unwrap(),
                ["v1", "auth", "token", "lookup-self"]
            )
            .as_str(),
            "http://127.0.0.1:8200/v1/auth/token/lookup-self"
        );
    }

    #[test]
    fn rejects_query_fragment_and_credentials_in_addr() {
        for bad in [
            "https://vault.example.net:8200/?x=1",
            "https://vault.example.net:8200?",
            "https://vault.example.net:8200#frag",
            "https://vault.example.net:8200/#",
            "http://127.0.0.1:8200/?namespace=a",
            "https://user:pw@vault.example.net:8200",
        ] {
            let err = check_addr(bad).unwrap_err();
            assert!(!format!("{err:#}").contains("pw@"), "{err:#}");
            assert!(VaultConfig::new(bad, "t", None).is_err(), "{bad}");
        }
    }

    #[test]
    fn addr_is_never_echoed() {
        for bad in [
            // invalid port: the parse error comes before the credential check
            "https://user:s3cr3t-pw@vault.example.net:99999",
            "https://user:s3cr3t-pw@vault.example.net:port",
            "not a url s3cr3t-pw",
            "https://vault.example.net/?token=s3cr3t-pw",
            "http://s3cr3t-pw.example.net",
            "ftp://s3cr3t-pw.example.net",
        ] {
            let text = format!("{:#}", check_addr(bad).unwrap_err());
            assert!(text.contains("VAULT_ADDR"), "{bad}: {text}");
            assert!(!text.contains("s3cr3t-pw"), "{bad}: {text}");
        }
    }

    #[test]
    fn token_is_validated_and_never_shown() {
        for bad in ["tok\n", "t\nok", "tök", "t ok", "t\tok", ""] {
            let err = VaultConfig::new("https://vault.example.net", bad, None).unwrap_err();
            let text = format!("{err:#}");
            assert!(text.contains("VAULT_TOKEN"), "{bad:?}: {text}");
            assert!(!text.contains("tok") && !text.contains("tök"), "{text}");
        }
        assert!(VaultConfig::new("https://v.example.net", "t", Some("a\nb".into())).is_err());
        let cfg = VaultConfig::new(
            "https://vault.example.net",
            "hvs.SecretToken42",
            Some("ns".into()),
        )
        .unwrap();
        let debug = format!("{cfg:?} {cfg:#?}");
        assert!(!debug.contains("SecretToken42"), "{debug}");
        assert!(
            debug.contains("vault.example.net") && debug.contains("redacted"),
            "{debug}"
        );
    }

    #[test]
    fn env_var_is_trimmed() {
        let name = format!("PGPP_TEST_ENV_VAR_{}", std::process::id());
        std::env::set_var(&name, " hvs.tok\n");
        assert_eq!(env_var(&name).as_deref(), Some("hvs.tok"));
        std::env::set_var(&name, " \n");
        assert_eq!(env_var(&name), None);
        std::env::remove_var(&name);
        assert_eq!(env_var(&name), None);
    }

    #[test]
    fn reads_capabilities() {
        let p = "secret/data/app";
        for body in [
            json!({"capabilities": ["read", "update"]}),
            json!({"secret/data/app": ["read", "update"]}),
            json!({"data": {"secret/data/app": ["read", "update"]}}),
        ] {
            assert_eq!(capabilities_of(&body, p).unwrap(), ["read", "update"]);
        }
        assert!(capabilities_of(&json!({"other": []}), p).is_none());
        assert!(capabilities_of(&json!({"capabilities": [1]}), p).is_none());
        assert_eq!(
            VaultTarget::parse("db/app", Some("team/kv"))
                .unwrap()
                .api_path(),
            "team/kv/data/db/app"
        );
    }

    #[test]
    fn accepts_https_and_loopback_http_only() {
        assert!(check_addr("https://vault.example.net:8200").is_ok());
        assert!(check_addr("http://127.0.0.1:8200").is_ok());
        assert!(check_addr("http://127.1.2.3:8200/").is_ok());
        assert!(check_addr("http://localhost:8200").is_ok());
        assert!(check_addr("http://[::1]:8200").is_ok());
        for bad in [
            "http://vault.example.net:8200",
            "http://10.0.0.5:8200",
            "http://127.0.0.1.example.net:8200",
            "ftp://vault.example.net",
            "vault.example.net:8200",
        ] {
            assert!(check_addr(bad).is_err(), "{bad}");
        }
        assert!(VaultConfig::new("http://vault.example.net", "t", None).is_err());
    }

    #[test]
    fn rejects_a_bad_ca_file() {
        let dir = std::env::temp_dir();
        let missing = dir.join(format!("pgpp-missing-{}.pem", std::process::id()));
        assert!(load_pem_bundle(&missing).is_err());
        let empty = dir.join(format!("pgpp-empty-{}.pem", std::process::id()));
        std::fs::write(&empty, "not a certificate\n").unwrap();
        assert!(load_pem_bundle(&empty).is_err());
        let _ = std::fs::remove_file(&empty);
    }

    #[test]
    fn builds_payload() {
        let p = build_payload("app", "pw", "2026-01-01T00:00:00Z");
        assert_eq!(
            p,
            json!({"data": {"username": "app", "password": "pw", "rotated_at": "2026-01-01T00:00:00Z"}})
        );
        assert!(p["data"]["password"].is_string());
        assert_eq!(
            p.as_object().unwrap().len(),
            1,
            "only the data key at top level"
        );
    }
}
