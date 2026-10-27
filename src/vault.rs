//! HashiCorp Vault KV v2 integration.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::{Certificate, Url};
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
#[derive(Debug, Clone)]
pub struct VaultConfig {
    /// Validated `VAULT_ADDR`.
    pub addr: Url,
    pub token: String,
    pub namespace: Option<String>,
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
        Ok(VaultConfig {
            addr,
            token: token.into(),
            namespace,
            client: build_client(root_certs)?,
        })
    }

    /// Reads the environment and validates everything (address, token,
    /// certificates, HTTP client) so that a misconfiguration is reported
    /// before any password is rotated.
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| std::env::var(name).ok().filter(|s| !s.is_empty());
        let addr = var("VAULT_ADDR").context("VAULT_ADDR is not set")?;
        let token = var("VAULT_TOKEN").context("VAULT_TOKEN is not set")?;
        let certs = root_certs_from_env()?;
        Self::with_root_certs(addr, token, var("VAULT_NAMESPACE"), &certs)
    }

    /// Request carrying the token and namespace headers.
    fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .request(method, url)
            .header("X-Vault-Token", self.token.as_str())
            .header("X-Vault-Request", "true");
        if let Some(ns) = &self.namespace {
            req = req.header("X-Vault-Namespace", ns.as_str());
        }
        req
    }
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
    let url =
        Url::parse(addr).with_context(|| format!("VAULT_ADDR {addr:?} is not a valid URL"))?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("VAULT_ADDR: credentials in the URL are not allowed (use VAULT_TOKEN)");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("VAULT_ADDR {addr:?}: a query string (?) or a fragment (#) is not allowed");
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
                    "VAULT_ADDR {addr:?}: plain http:// is only accepted for a loopback host \
                     (127.0.0.0/8, ::1, localhost); use https:// (set VAULT_CACERT or \
                     VAULT_CAPATH for a private CA)"
                )
            }
        }
        other => bail!("VAULT_ADDR {addr:?}: unsupported scheme {other:?}"),
    }
}

/// Extra root certificates: `VAULT_CACERT` (one PEM file, possibly a bundle)
/// takes precedence over `VAULT_CAPATH` (a directory of `*.pem` / `*.crt`
/// files), as in the official Vault client.
fn root_certs_from_env() -> Result<Vec<Certificate>> {
    let var = |name: &str| std::env::var(name).ok().filter(|s| !s.is_empty());
    if let Some(file) = var("VAULT_CACERT") {
        return load_pem_bundle(Path::new(&file)).with_context(|| format!("VAULT_CACERT {file:?}"));
    }
    if let Some(dir) = var("VAULT_CAPATH") {
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
/// (no redirect) and accepts `VAULT_TOKEN`:
/// `GET {addr}/v1/auth/token/lookup-self`, allowed by Vault's default policy.
/// An expired or revoked token, an unreachable host or a redirect is thus
/// reported while the password is still unchanged.  The response body (token
/// metadata) is not read.
pub async fn preflight(cfg: &VaultConfig) -> Result<()> {
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
    if !status.is_success() {
        bail!(
            "Vault refused VAULT_TOKEN at {url}: HTTP {status}{} (expired or revoked token?)",
            error_body(resp).await
        );
    }
    Ok(())
}

fn redirect_message(status: reqwest::StatusCode, url: &Url) -> String {
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
            assert!(!err.to_string().contains("pw@"), "{err}");
            assert!(VaultConfig::new(bad, "t", None).is_err(), "{bad}");
        }
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
