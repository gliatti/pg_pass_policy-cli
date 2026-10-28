//! HashiCorp Vault KV v2 integration.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::{Certificate, StatusCode, Url};
use serde::Serialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

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
    /// to another endpoint than the one the operator typed; only the slashes
    /// at both ends are dropped, an empty segment is refused everywhere,
    /// including at the boundary of the mount (`secret//app`).
    pub fn parse(kv_path: &str, mount: Option<&str>) -> Result<Self> {
        let kv_path = kv_path.trim().trim_matches('/');
        if kv_path.is_empty() {
            bail!("--vault-kv: empty path");
        }
        let (mount, path) = match mount {
            Some(m) => (m.trim().trim_matches('/').to_string(), kv_path.to_string()),
            None => match kv_path.split_once('/') {
                Some((m, p)) => (m.to_string(), p.to_string()),
                None => bail!(
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

    /// Warning for a target parsed with an explicit `--vault-mount`, whose
    /// `--vault-kv` is then the path below the mount: when that path starts
    /// with the mount itself (`--vault-mount kv --vault-kv kv/app`), the
    /// secret goes to `kv/data/kv/app`, which is rarely what was meant.
    pub fn repeated_mount_warning(&self) -> Option<String> {
        let repeated = self.path == self.mount
            || self
                .path
                .strip_prefix(&self.mount)
                .is_some_and(|rest| rest.starts_with('/'));
        repeated.then(|| {
            format!(
                "--vault-kv \"{path}\" starts with the mount \"{mount}\" given by \
                 --vault-mount: the secret is written to {api}; with --vault-mount, \
                 --vault-kv is the path below the mount (drop the \"{mount}/\" prefix)",
                path = self.path,
                mount = self.mount,
                api = self.api_path(),
            )
        })
    }

    /// Vault path of the KV v2 data endpoint (`{mount}/data/{path}`), as
    /// used by policies and by `sys/capabilities-self`.
    pub fn api_path(&self) -> String {
        format!("{}/data/{}", self.mount, self.path)
    }

    /// URL of the KV v2 data endpoint, below the path of `addr` (if any).
    pub fn url(&self, addr: &Url) -> Url {
        self.kv_url(addr, "data")
    }

    /// URL of the KV v2 metadata endpoint (`{mount}/metadata/{path}`),
    /// read by the preflight to tell an existing secret from a new one.
    pub fn metadata_url(&self, addr: &Url) -> Url {
        self.kv_url(addr, "metadata")
    }

    fn kv_url(&self, addr: &Url, kind: &str) -> Url {
        let segments = std::iter::once("v1")
            .chain(self.mount.split('/'))
            .chain(std::iter::once(kind))
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
    /// HTTP client built once (with the extra root certificates and the
    /// connection timeout) and used for every request: token preflight and
    /// secret write.
    client: reqwest::Client,
    /// Longest duration of a request, connection and response included
    /// ([`REQUEST_TIMEOUT`] unless given to [`VaultConfig::with_timeout`]).
    timeout: Duration,
}

/// Outcome of a successful [`preflight`]: the warnings to print, and
/// whether the token was accepted on `update` alone because the secret
/// existed ([`check_update_only`]).  The caller keeps it with the delivery
/// and hands `update_only` to [`explain_refusal`]: only the handling of a
/// 403 on the write depends on it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preflight {
    pub warnings: Vec<String>,
    pub update_only: bool,
}

/// Default longest duration of a Vault request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest duration of the connection (TCP and TLS handshake) to Vault,
/// shorter than the request timeout: a connection that does not succeed in
/// time then fails as a connection error (`is_connect()`), which says that
/// nothing was sent, instead of a request timeout, which does not.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection timeout used with a request timeout: [`CONNECT_TIMEOUT`],
/// at most half of the request timeout.
fn connect_timeout_for(request: Duration) -> Duration {
    CONNECT_TIMEOUT.min(request / 2)
}

impl VaultConfig {
    /// Builds a configuration; `addr` must use `https://`, or `http://` on a
    /// loopback host only.
    pub fn new(
        addr: impl AsRef<str>,
        token: impl Into<String>,
        namespace: Option<String>,
    ) -> Result<Self> {
        Self::with_root_certs(addr, token, namespace, &[], REQUEST_TIMEOUT)
    }

    /// Same as [`VaultConfig::new`] with another request timeout (tests);
    /// the connection timeout follows ([`connect_timeout_for`]).
    pub fn with_timeout(
        addr: impl AsRef<str>,
        token: impl Into<String>,
        namespace: Option<String>,
        timeout: Duration,
    ) -> Result<Self> {
        Self::with_root_certs(addr, token, namespace, &[], timeout)
    }

    /// Same as [`VaultConfig::with_timeout`], trusting in addition
    /// `root_certs` (private CA) besides the system and webpki stores.  The
    /// HTTP client is built here, once, with every setting.
    pub fn with_root_certs(
        addr: impl AsRef<str>,
        token: impl Into<String>,
        namespace: Option<String>,
        root_certs: &[Certificate],
        timeout: Duration,
    ) -> Result<Self> {
        let (addr, pinned) = check_addr_pinned(addr.as_ref())?;
        let direct = is_loopback_target(&addr);
        let mut token = header_value(&token.into(), "VAULT_TOKEN")?;
        token.set_sensitive(true);
        let namespace = namespace
            .map(|ns| header_value(&ns, "VAULT_NAMESPACE"))
            .transpose()?;
        Ok(VaultConfig {
            addr,
            token,
            namespace,
            client: build_client(root_certs, &pinned, direct, connect_timeout_for(timeout))?,
            timeout,
        })
    }

    /// Reads the environment and validates everything (address, token,
    /// certificates, HTTP client) so that a misconfiguration is reported
    /// before any password is rotated.  Surrounding whitespace (a final
    /// newline copied from a token file, for instance) is removed from the
    /// values sent as HTTP headers (`VAULT_TOKEN`, `VAULT_NAMESPACE`) only;
    /// `VAULT_ADDR`, `VAULT_CACERT` and `VAULT_CAPATH` are used as given.
    pub fn from_env() -> Result<Self> {
        let addr = env_var("VAULT_ADDR").context("VAULT_ADDR is not set")?;
        let token = clean(env_var("VAULT_TOKEN")).context("VAULT_TOKEN is not set")?;
        let namespace = clean(env_var("VAULT_NAMESPACE"));
        let certs = root_certs_from_env()?;
        Self::with_root_certs(addr, token, namespace, &certs, REQUEST_TIMEOUT)
    }

    /// Request carrying the token and namespace headers.
    fn request(&self, method: reqwest::Method, url: Url) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .request(method, url)
            .timeout(self.timeout)
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

/// Non-empty value of an environment variable, as given.
fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

/// Non-empty path from an environment variable, as given (not necessarily
/// UTF-8).
fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Value meant for an HTTP header without surrounding whitespace, `None`
/// when nothing is left.
fn clean(value: Option<String>) -> Option<String> {
    value
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
/// `check_addr`.  A redirect is reported as an error instead.  `pinned`
/// (a localhost name) replaces the resolution of that name by the
/// loopback address set by `check_addr_pinned`.  `connect_timeout` bounds the
/// connection alone (see [`CONNECT_TIMEOUT`]).
///
/// `direct` (a loopback target, see [`is_loopback_target`]) disables the
/// proxies of the environment (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`):
/// a local Vault agent must be reached on this host, never through a proxy
/// that would resolve `localhost` on its own side and see the token (and,
/// with `http://`, the password) in clear.  A remote address keeps the
/// system proxy settings, `NO_PROXY` included, as the official Vault client
/// does: the proxy then relays a TLS tunnel (`CONNECT`) whose certificate is
/// still verified against `VAULT_ADDR`.
fn build_client(
    root_certs: &[Certificate],
    pinned: &Pinned,
    direct: bool,
    connect_timeout: Duration,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout);
    if direct {
        builder = builder.no_proxy();
    }
    if let Some((host, addr)) = pinned {
        builder = builder.resolve(host, *addr);
    }
    for cert in root_certs {
        builder = builder.add_root_certificate(cert.clone());
    }
    builder.build().context("cannot build the HTTP client")
}

/// Checks `VAULT_ADDR` and returns it parsed: a URL whose scheme is `https`,
/// or `http` when the host is loopback, without query string, fragment or
/// credentials.  Plain HTTP to a remote host would send the token and the
/// password in clear; a query or a fragment would be carried over to (or
/// truncate) every endpoint URL.  See `check_addr_pinned` for the loopback
/// rule.
pub fn check_addr(addr: &str) -> Result<Url> {
    Ok(check_addr_pinned(addr)?.0)
}

/// Host name of an `http://` or `https://` localhost address with the
/// loopback address it is pinned to (`127.0.0.1`, port 0: the client takes
/// the port of the URL); the HTTP client connects there without resolving
/// it.
type Pinned = Option<(String, SocketAddr)>;

/// [`check_addr`], returning in addition the address a localhost name is
/// pinned to.  With `http://`, the host must be a literal loopback address
/// (`127.0.0.0/8`, `[::1]`), or a localhost name ([`is_localhost_name`]:
/// `localhost`, `localhost.`, `vault.localhost`).  Such a name, with
/// `http://` or `https://`, is never resolved (neither `/etc/hosts` nor
/// DNS, which could point it anywhere, nor a blocking call): RFC 6761
/// reserves it for the loopback interface, and the HTTP client connects to
/// `127.0.0.1` alone on the port of the URL, under that name (`Host`
/// header, and TLS name checked against the certificate).  Do not add
/// `[::1]` as a fallback: deliberate decision, see README "Limites
/// connues" (a single address, never a happy eyeballs race, and the
/// address reached is the one written; an IPv6-only agent is reached with
/// `[::1]` written in the URL).
fn check_addr_pinned(addr: &str) -> Result<(Url, Pinned)> {
    // The value is never echoed in the messages: it may hold credentials
    // (`user:pw@`) that are only detected once the URL is parsed.
    let url = Url::parse(addr).context("VAULT_ADDR is not a valid URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        bail!("VAULT_ADDR: credentials in the URL are not allowed (use VAULT_TOKEN)");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("VAULT_ADDR: a query string (?) or a fragment (#) is not allowed");
    }
    // `url` lower-cases the host and normalises IPv4 (`127.1`)
    let host = url.host_str().unwrap_or("");
    match url.scheme() {
        "https" => {}
        "http" if literal_loopback(host) || is_localhost_name(host) => {}
        "http" => bail!(
            "VAULT_ADDR: plain http:// is only accepted for a loopback host \
             (127.0.0.0/8, [::1], localhost or a name under it); use https:// \
             (set VAULT_CACERT or VAULT_CAPATH for a private CA)"
        ),
        other => bail!("VAULT_ADDR: unsupported scheme {other:?} (use https://)"),
    }
    // a localhost name (RFC 6761): pinned, never resolved; port 0 lets the
    // client take the port of the URL
    let pinned = is_localhost_name(host)
        .then(|| (host.to_string(), SocketAddr::from((Ipv4Addr::LOCALHOST, 0))));
    Ok((url, pinned))
}

/// True when `VAULT_ADDR` designates this host, with `http://` or
/// `https://`: a localhost name ([`is_localhost_name`]) or a literal
/// loopback address ([`literal_loopback`]).  Such a target is reached
/// directly, never through a proxy, which would resolve the name on its
/// own side (see [`build_client`]).
fn is_loopback_target(url: &Url) -> bool {
    let host = url.host_str().unwrap_or("");
    is_localhost_name(host) || literal_loopback(host)
}

/// True for `localhost` and the names under it (`vault.localhost`), with
/// or without the final dot of a fully qualified name (`localhost.`,
/// `vault.localhost.`): RFC 6761 reserves them for the loopback interface.
/// `host` is lower-cased by `url`; the comparison ignores ASCII case all
/// the same.  A name that merely contains `localhost`
/// (`localhost.example.net`, `my-localhost`) is not one of them.
fn is_localhost_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    name == "localhost" || name.ends_with(".localhost")
}

/// True for a literal loopback address as `url` prints it (`127.0.0.1`,
/// `[::1]`); a name is never resolved here.
fn literal_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Extensions of the files of `VAULT_CAPATH` that are loaded, compared
/// without regard to ASCII case (`CA.PEM`, `root.Crt`); PEM content in every
/// case, a DER `.cer` is refused as not PEM.
const CAPATH_EXTENSIONS: [&str; 3] = ["pem", "crt", "cer"];

/// `*.pem / *.crt / *.cer`, for the messages.
fn capath_patterns() -> String {
    CAPATH_EXTENSIONS
        .iter()
        .map(|e| format!("*.{e}"))
        .collect::<Vec<_>>()
        .join(" / ")
}

/// Files of the `VAULT_CAPATH` directory that are loaded, sorted.
fn capath_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("VAULT_CAPATH {dir:?}: cannot read the directory"))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| CAPATH_EXTENSIONS.iter().any(|x| e.eq_ignore_ascii_case(x)))
        })
        .collect();
    paths.sort();
    Ok(paths)
}

/// Extra root certificates: `VAULT_CACERT` (one PEM file, possibly a bundle)
/// takes precedence over `VAULT_CAPATH` (a directory of `*.pem` / `*.crt` /
/// `*.cer` files, see [`CAPATH_EXTENSIONS`]), as in the official Vault
/// client.
fn root_certs_from_env() -> Result<Vec<Certificate>> {
    if let Some(file) = env_path("VAULT_CACERT") {
        return load_pem_bundle(&file).with_context(|| format!("VAULT_CACERT {file:?}"));
    }
    if let Some(dir) = env_path("VAULT_CAPATH") {
        let mut certs = Vec::new();
        for p in &capath_files(&dir)? {
            certs.extend(
                load_pem_bundle(p).with_context(|| format!("VAULT_CAPATH: {}", p.display()))?,
            );
        }
        if certs.is_empty() {
            bail!(
                "VAULT_CAPATH {dir:?}: no certificate found ({})",
                capath_patterns()
            );
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

/// Longest body read (and discarded) by [`drain`]: past it the connection
/// is dropped instead of being reused.
const DRAIN_LIMIT: usize = 64 * 1024;

/// Reads the body of `resp` to its end, chunk by chunk, without keeping it
/// (the token metadata of `lookup-self` is never parsed), so that the
/// connection goes back to the pool and is reused by the next request
/// instead of being closed with unread data.  A read error, or a body
/// larger than [`DRAIN_LIMIT`], only costs a new connection.
async fn drain(mut resp: reqwest::Response) {
    let mut read = 0usize;
    while let Ok(Some(chunk)) = resp.chunk().await {
        read += chunk.len();
        if read > DRAIN_LIMIT {
            break;
        }
    }
}

/// Checks, before any rotation, that Vault is reachable at `VAULT_ADDR`
/// (no redirect), that it accepts `VAULT_TOKEN` and that the token may write
/// the target, so that these failures are reported while the password is
/// still unchanged.  Two requests, each of which must answer 2xx:
///
/// 1. `GET {addr}/v1/auth/token/lookup-self` (allowed by Vault's `default`
///    policy).  Vault answers 403 "permission denied", never 401, for an
///    expired, revoked or unknown token: a 403 is therefore a refusal like
///    any other non-2xx status.  The response body (token metadata) is
///    read to its end and discarded, never parsed ([`drain`]).
/// 2. `POST {addr}/v1/sys/capabilities-self` with the KV v2 data path: an
///    error when this request is refused, or when the capabilities of the
///    token on that path are not enough to write it ([`can_write`]: `root`,
///    or both `create` and `update`).  When the answer cannot be read, a
///    warning is returned and the write is attempted after the rotation.
/// 3. Only for a token that has `update` without `create` (nor `root`):
///    `GET {addr}/v1/{mount}/metadata/{path}` ([`check_update_only`]).  A
///    200 says that the secret exists, and every later write is then an
///    update: `update` alone is enough.  A 404 says that it does not exist
///    yet, and its first write needs `create`.  Any other answer (403 when
///    the token may not read the metadata, network error) leaves the
///    question open, and both `create` and `update` are required.
///
/// A token created with `-no-default-policy` fails the first request: the
/// caller skips this preflight on an explicit request only
/// (`--vault-skip-preflight`).  Returns the warnings, which the caller
/// prints, and whether the token was accepted on `update` alone
/// ([`Preflight`]).
pub async fn preflight(cfg: &VaultConfig, target: &VaultTarget) -> Result<Preflight> {
    let mut warnings = Vec::new();
    let mut update_only = false;

    // Two requests on purpose: `capabilities-self` alone would also refuse
    // an expired, revoked or unknown token, but its error does not tell a
    // bad token from a token without permission on `sys/capabilities-self`.
    // `lookup-self` first pins the failure on the token itself; the extra
    // round trip is accepted for that more precise message.
    let url = endpoint(&cfg.addr, ["v1", "auth", "token", "lookup-self"]);
    let resp = send_checked(
        cfg.request(reqwest::Method::GET, url.clone()),
        &url,
        Call::Preflight,
    )
    .await?;
    drain(resp).await;

    let path = target.api_path();
    let url = endpoint(&cfg.addr, ["v1", "sys", "capabilities-self"]);
    let resp = send_checked(
        cfg.request(reqwest::Method::POST, url.clone())
            .json(&json!({ "paths": [path] })),
        &url,
        Call::Preflight,
    )
    .await?;
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
        Some(caps) if can_write(&caps) => {}
        Some(caps) if has_capability(&caps, "update") => {
            check_update_only(cfg, target, &caps).await?;
            update_only = true;
        }
        Some(caps) => bail!(cannot_write_message(&path, &caps, "")),
    }
    Ok(Preflight {
        warnings,
        update_only,
    })
}

/// Refusal of the preflight for a token whose capabilities on `path` are
/// not enough to write it; `why` (empty or starting with `; `) tells what
/// the metadata read found.
fn cannot_write_message(path: &str, caps: &[String], why: &str) -> String {
    format!(
        "VAULT_TOKEN may not write \"{path}\": its capabilities there are [{}] \
         (create and update required, or root, or update alone on an existing \
         secret{why}; --vault-skip-preflight skips this check)",
        caps.join(", ")
    )
}

/// Preflight of a token that has `update` without `create`: accepted only
/// when the secret already exists, which its KV v2 metadata tells (Vault
/// asks for `update` on a path whose metadata exists, `create` otherwise).
/// The metadata body (versions, custom metadata) is read to its end and
/// discarded, never parsed.  An answer other than 200 or 404, or a
/// failed request, cannot tell whether the secret exists: the token is
/// then refused as without `create`.
///
/// This is a check-then-act: the secret may be deleted (metadata included)
/// between this check and the write after the rotation, which then needs
/// `create` and is refused with 403.  The write reads the metadata again to
/// tell that case from a token expired, revoked or deprived of its policy
/// since ([`explain_update_only_refusal`]); nothing else is changed (the
/// rotation is already done by then).
async fn check_update_only(cfg: &VaultConfig, target: &VaultTarget, caps: &[String]) -> Result<()> {
    let path = target.api_path();
    let url = target.metadata_url(&cfg.addr);
    let why = match cfg.request(reqwest::Method::GET, url.clone()).send().await {
        Ok(resp) if resp.status() == StatusCode::OK => {
            drain(resp).await;
            return Ok(());
        }
        Ok(resp) if resp.status() == StatusCode::NOT_FOUND => {
            drain(resp).await;
            format!("; the secret does not exist yet ({url} answered 404) and its first write needs create")
        }
        Ok(resp) => {
            let status = resp.status();
            drain(resp).await;
            format!(
                "; whether the secret exists could not be checked: {url} answered HTTP {status} \
                 (read on the metadata path needed)"
            )
        }
        Err(e) => format!(
            "; whether the secret exists could not be checked: request to {url} failed ({e})"
        ),
    };
    bail!(cannot_write_message(&path, caps, &why))
}

/// True when the capabilities of a token on a KV v2 data path let it write
/// the secret whether it exists or not: `root`, or both `create` (first
/// version of the secret) and `update` (any later version, i.e. every
/// rotation after the first one).  `create` alone would pass the preflight
/// and then be refused by Vault after the rotation once the secret exists;
/// `update` alone would be refused for a secret not written yet.  `sudo`
/// only opens root-protected paths and grants no write by itself, it is not
/// enough either.  `update` alone is enough for a secret that already
/// exists, which `capabilities-self` cannot tell: [`check_update_only`]
/// reads its metadata for that case.
fn can_write(caps: &[String]) -> bool {
    has_capability(caps, "root")
        || (has_capability(caps, "create") && has_capability(caps, "update"))
}

fn has_capability(caps: &[String], name: &str) -> bool {
    caps.iter().any(|c| c == name)
}

/// Kind of a request sent by [`send_checked`], for the wording of its
/// errors.
#[derive(Debug, Clone, Copy)]
enum Call {
    /// Preflight request, before the rotation.
    Preflight,
    /// Write of the secret, after the rotation: a refusal is a
    /// [`WriteRefused`].
    Write,
}

/// Explanation added to a 403 on a write after a preflight that accepted
/// `update` alone, when a new read of the metadata answers 404
/// ([`explain_refusal`]).
pub const METADATA_DISAPPEARED: &str = "secret metadata disappeared: the token needs create \
     (the preflight accepted update alone because the secret existed; it was deleted since)";

/// Explanation added to that 403 when the metadata did not answer 404: the
/// secret may still exist, the permission itself changed.
pub const REFUSED_SINCE_PREFLIGHT: &str = "permission denied since the preflight: the token \
     may have expired or been revoked, or its policy may have changed";

/// HTTP status other than 2xx or a redirect answered to the write of the
/// secret ([`Call::Write`]); its text is the whole message.
#[derive(Debug)]
struct WriteRefused {
    status: StatusCode,
    message: String,
}

impl std::fmt::Display for WriteRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WriteRefused {}

/// Sends a request and returns the response when its status is 2xx.  A
/// network error, a redirect (never followed) or any other status is an
/// error, with the status and the response body.  For a preflight request,
/// 401 and 403 are reported as a refused token, with the hint for a token
/// without the default policy.
async fn send_checked(
    req: reqwest::RequestBuilder,
    url: &Url,
    call: Call,
) -> Result<reqwest::Response> {
    let request = match call {
        Call::Preflight => "Vault preflight request",
        Call::Write => "Vault request",
    };
    let resp = req
        .send()
        .await
        .map_err(|e| anyhow::Error::new(e).context(format!("{request} to {url} failed")))?;
    let status = resp.status();
    if status.is_redirection() {
        bail!(redirect_message(status, url));
    }
    if status.is_success() {
        return Ok(resp);
    }
    let body = error_body(resp).await;
    match call {
        Call::Write => Err(anyhow::Error::new(WriteRefused {
            status,
            message: format!("Vault refused the write to {url}: HTTP {status}{body}"),
        })),
        Call::Preflight if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
            bail!(
                "Vault refused VAULT_TOKEN at {url}: HTTP {status}{body} (expired, revoked or \
                 unknown token, or no permission on this endpoint; a token created with \
                 -no-default-policy needs --vault-skip-preflight)"
            )
        }
        Call::Preflight => bail!("{request} to {url} failed: HTTP {status}{body}"),
    }
}

/// True when a failed Vault request may have been received by Vault: the
/// error came after the connection was established (no answer within the
/// timeout, connection closed while waiting for or reading the response,
/// unreadable body).  An error raised before anything was sent (DNS,
/// connection refused or timed out, TLS handshake, invalid request) or an
/// answer of Vault (HTTP status, redirect) gives `false`.  A connection
/// that does not succeed in time is a connection error ([`CONNECT_TIMEOUT`]
/// is shorter than the request timeout), not a request timeout.  Callers
/// that know whether the body was sent (`body_sent` of [`send_write`])
/// combine both.
pub fn may_have_been_received(err: &anyhow::Error) -> bool {
    err.chain()
        .find_map(|e| e.downcast_ref::<reqwest::Error>())
        .is_some_and(|e| !e.is_connect() && !e.is_builder())
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

/// Writes the payload, the request alone: a refusal of Vault is returned as
/// it is (a [`WriteRefused`]), never explained ([`explain_refusal`] only
/// explains a refusal after an `update`-only preflight).  Errors (network,
/// HTTP status) are reported with the status and the response body, which
/// Vault fills with its own error list; the payload itself is never
/// included.  The body is serialised into a buffer wiped when reqwest drops
/// it (see [`zeroizing_json`]).  A rotation goes through
/// `commands::vault_delivery`, which calls [`send_write`] and
/// [`explain_refusal`] apart.  `body_sent` is set once the
/// HTTP client starts to send the body (see [`TrackedBody`]): while it is
/// still false, Vault cannot have written the secret, whatever the error
/// (or the interruption), the request being incomplete without its body.
pub async fn send_write(
    cfg: &VaultConfig,
    target: &VaultTarget,
    payload: &Value,
    body_sent: Arc<AtomicBool>,
) -> Result<()> {
    let url = target.url(&cfg.addr);
    let body = zeroizing_json(payload)?;
    let body = TrackedBody {
        data: Some(Bytes::from_owner(body)),
        sent: body_sent,
    };
    let req = cfg
        .request(reqwest::Method::POST, url.clone())
        .header(CONTENT_TYPE, "application/json")
        .body(reqwest::Body::wrap(body));
    send_checked(req, &url, Call::Write).await.map(drop)
}

/// Bound of the new read of the metadata made by [`explain_refusal`]: the
/// refusal is already certain, the read only refines its explanation and
/// must not hold the end of a rotation for the whole request timeout.
pub const REREAD_TIMEOUT: Duration = Duration::from_secs(5);

/// Error of a write sent by [`send_write`].  A 403 after a preflight that
/// accepted `update` alone (`update_only`) is a refusal of Vault, certain
/// from its answer: the secret was not written.  The secret may have been
/// deleted since (its write then needs `create`), or the token may have
/// expired, been revoked or lost its policy.  A second read of the
/// metadata tells them apart: 404 confirms the deletion
/// ([`METADATA_DISAPPEARED`]); any other answer, or a failed request,
/// gives the cautious [`REFUSED_SINCE_PREFLIGHT`] with what that read
/// found.  That read is bounded by `timeout` and abandoned when `cancel`
/// ends (Ctrl-C): the result is then [`REFUSED_SINCE_PREFLIGHT`] followed
/// by `(no answer within <timeout>)`, `(interrupted before the check)` (a
/// Ctrl-C already received: the read is not sent) or `(interrupted)`
/// (during the read), never « may or may not have been written ».  The error of that
/// read is only quoted as text: the result stays an answer of Vault to the
/// write ([`may_have_been_received`] is false).  Any other error is
/// returned as it is.
pub async fn explain_refusal(
    cfg: &VaultConfig,
    target: &VaultTarget,
    refused: anyhow::Error,
    update_only: bool,
    timeout: Duration,
    cancel: impl std::future::Future<Output = ()>,
) -> anyhow::Error {
    let forbidden = refused
        .downcast_ref::<WriteRefused>()
        .is_some_and(|r| r.status == StatusCode::FORBIDDEN);
    if !(update_only && forbidden) {
        return refused;
    }
    let url = target.metadata_url(&cfg.addr);
    let reread = async {
        match cfg.request(reqwest::Method::GET, url.clone()).send().await {
            Ok(resp) => {
                let status = resp.status();
                drain(resp).await;
                if status == StatusCode::NOT_FOUND {
                    None
                } else {
                    Some(format!("{url} answered HTTP {status}"))
                }
            }
            Err(e) => Some(format!("request to {url} failed ({e})")),
        }
    };
    let mut cancel = std::pin::pin!(cancel);
    // a Ctrl-C already received skips the read
    let already = tokio::select! {
        biased;
        () = &mut cancel => true,
        () = std::future::ready(()) => false,
    };
    let found = if already {
        "interrupted before the check".to_string()
    } else {
        tokio::select! {
            biased;
            () = &mut cancel => "interrupted".to_string(),
            r = tokio::time::timeout(timeout, reread) => match r {
                Ok(None) => return anyhow::anyhow!("{refused:#}: {METADATA_DISAPPEARED}"),
                Ok(Some(found)) => found,
                Err(_) => format!("no answer within {timeout:?}"),
            },
        }
    };
    anyhow::anyhow!("{refused:#}: {REFUSED_SINCE_PREFLIGHT} ({found})")
}

/// Request body made of a single chunk, which raises `sent` when the HTTP
/// client polls it for the first time.  hyper polls a request body only
/// once the request is on a connection (established, TLS included) and
/// its headers are queued: as long as `sent` is false, no byte of the body
/// has left the process.  The exact size is announced (`Content-Length`
/// header, as with a plain buffer).
///
/// « Sent » therefore means « handed to the write buffer of the
/// connection » (hyper, then rustls and the kernel socket), not « received
/// by Vault »: once `sent` is true, the bytes may still be in a buffer of
/// this process or of the kernel, or lost with the connection.  This is
/// why a failure after that point is reported with the cautious « may or
/// may not have been written », never as a write that took place; only
/// `sent == false` is a certainty (nothing reached Vault).
struct TrackedBody {
    data: Option<Bytes>,
    sent: Arc<AtomicBool>,
}

impl http_body::Body for TrackedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<http_body::Frame<Bytes>, Self::Error>>> {
        self.sent.store(true, Ordering::SeqCst);
        Poll::Ready(self.data.take().map(|d| Ok(http_body::Frame::data(d))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.data.as_ref().map_or(0, |d| d.len() as u64))
    }
}

/// JSON text of `payload` in a buffer allocated once at its exact size (a
/// growing `Vec` would leave unwiped copies behind each reallocation) and
/// wiped when dropped.  Used for the Vault body.  Copies made further down
/// (hyper's write buffer, rustls' TLS records) are not under the control of
/// pgpp.
pub fn zeroizing_json<T: Serialize + ?Sized>(payload: &T) -> Result<Zeroizing<Vec<u8>>> {
    zeroizing_json_with(payload, false)
}

/// Same as [`zeroizing_json`], followed by a newline, which is counted in
/// the allocation: pushing it afterwards onto the exact-size buffer would
/// reallocate it and leave the first, unwiped copy behind.  Used for the
/// JSON output of a rotation with `--show`.
pub fn zeroizing_json_line<T: Serialize + ?Sized>(payload: &T) -> Result<Zeroizing<Vec<u8>>> {
    zeroizing_json_with(payload, true)
}

fn zeroizing_json_with<T: Serialize + ?Sized>(
    payload: &T,
    newline: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, payload).context("cannot serialise the JSON text")?;
    let size = count.0 + usize::from(newline);
    let mut buf = Zeroizing::new(Vec::with_capacity(size));
    serde_json::to_writer(&mut *buf, payload).context("cannot serialise the JSON text")?;
    if newline {
        buf.push(b'\n');
    }
    // a payload whose serialisation changed between the two passes would
    // have grown the buffer: refuse it rather than hide the copy
    if buf.len() != size {
        bail!("cannot serialise the JSON text: size changed between two passes");
    }
    Ok(buf)
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
            "secret//app",
            "secret///app",
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
        assert!(VaultTarget::parse("a//b", Some("kv")).is_err());
        assert!(VaultTarget::parse("x", Some("team//kv")).is_err());
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
            t.metadata_url(&check_addr("https://proxy.example.net/vault/").unwrap())
                .as_str(),
            "https://proxy.example.net/vault/v1/team/kv/metadata/db/app"
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
    fn header_values_are_cleaned() {
        assert_eq!(clean(Some(" hvs.tok\n".into())).as_deref(), Some("hvs.tok"));
        assert_eq!(clean(Some("\tns-a\r\n".into())).as_deref(), Some("ns-a"));
        assert_eq!(clean(Some(" \n".into())), None);
        assert_eq!(clean(Some(String::new())), None);
        assert_eq!(clean(None), None);
        // inner whitespace is kept, then refused by header_value
        assert_eq!(clean(Some(" a b ".into())).as_deref(), Some("a b"));
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
    fn http_localhost_is_pinned_without_resolution() {
        // literal loopback addresses are not pinned
        for addr in [
            "http://127.0.0.1:8200",
            "http://[::1]:8200",
            "http://127.1:8200",
        ] {
            assert!(check_addr_pinned(addr).unwrap().1.is_none(), "{addr}");
        }
        // every localhost name (is_localhost_name), with http:// or
        // https://, is pinned to 127.0.0.1 alone (never [::1]) on the port of the URL
        // under its own name,
        // whatever its case and whatever the system would resolve: names
        // no resolver knows are accepted the same way
        for addr in [
            "http://localhost:8200",
            "http://LocalHost:8200/",
            "http://localhost",
            "http://localhost.:8200",
            "http://vault.localhost:8200",
            "http://Vault.LocalHost.:8200",
            "http://pgpp-no-such-name.a.b.localhost:9",
            "https://localhost:8200",
            "https://vault.localhost",
        ] {
            let (url, pinned) = check_addr_pinned(addr).unwrap();
            let (host, pinned) = pinned.expect("a localhost name is pinned");
            assert_eq!(host, url.host_str().unwrap(), "{addr}");
            // port 0: resolve() makes reqwest take the port of the URL;
            // covered end to end by tests/vault.rs
            // http_localhost_reaches_the_pinned_loopback_address
            assert_eq!(pinned, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), "{addr}");
        }
        // other https names are not pinned
        assert!(check_addr_pinned("https://vault.example.net:8200")
            .unwrap()
            .1
            .is_none());
        // other names are refused without resolution, even close ones
        for bad in [
            "http://localhost..:8200",
            "http://localhost.example.net:8200",
            "http://my-localhost:8200",
            "http://[::ffff:127.0.0.1]:8200",
            "http://0.0.0.0:8200",
        ] {
            assert!(check_addr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_loopback_targets_bypass_the_proxy() {
        for addr in [
            "http://127.0.0.1:8200",
            "https://127.0.0.1:8200",
            "http://127.9.8.7:8200",
            "http://[::1]:8200",
            "https://[::1]:8200/vault",
            "http://localhost:8200",
            "https://localhost:8200",
            "https://LocalHost:8200/vault",
            "https://localhost.:8200",
            "https://vault.localhost:8200",
            "https://Vault.LocalHost.:8200/v",
            "https://a.b.localhost:8200",
        ] {
            assert!(is_loopback_target(&check_addr(addr).unwrap()), "{addr}");
        }
        // remote: the system proxy settings apply
        for addr in [
            "https://vault.example.net:8200",
            "https://10.0.0.5:8200",
            "https://localhost.example.net:8200",
            "https://localhost.example.net.:8200",
            "https://my-localhost:8200",
            "https://notlocalhost:8200",
            "https://localhost..:8200",
            "https://[::ffff:127.0.0.1]:8200",
        ] {
            assert!(!is_loopback_target(&check_addr(addr).unwrap()), "{addr}");
        }
    }

    #[test]
    fn localhost_names_are_recognised() {
        for name in [
            "localhost",
            "localhost.",
            "LOCALHOST",
            "vault.localhost",
            "vault.localhost.",
            "a.b.localhost",
        ] {
            assert!(is_localhost_name(name), "{name}");
        }
        for name in [
            "",
            ".",
            "localhost..",
            "localhost.example.net",
            "my-localhost",
            "notlocalhost",
            "localhostx",
            "127.0.0.1",
        ] {
            assert!(!is_localhost_name(name), "{name}");
        }
    }

    #[test]
    fn warns_when_the_mount_is_repeated_in_the_path() {
        let warn = |kv, mount| {
            VaultTarget::parse(kv, Some(mount))
                .unwrap()
                .repeated_mount_warning()
        };
        let w = warn("kv/app", "kv").expect("repeated mount");
        assert!(w.contains("kv/data/kv/app"), "{w}");
        assert!(warn("kv", "kv").is_some());
        assert!(warn("team/kv/app", "team/kv").is_some());
        assert!(warn("app", "kv").is_none());
        assert!(warn("kvx/app", "kv").is_none());
        assert!(warn("db/kv/app", "kv").is_none());
    }

    #[test]
    fn json_body_is_serialised_at_its_exact_size() {
        let p = build_payload("app", "pw-é\"x", "now");
        let body = zeroizing_json(&p).unwrap();
        assert_eq!(body.as_slice(), serde_json::to_vec(&p).unwrap().as_slice());
        assert_eq!(body.capacity(), body.len(), "no reallocation");
        let line = zeroizing_json_line(&p).unwrap();
        assert_eq!(
            line.capacity(),
            line.len(),
            "no reallocation for the newline"
        );
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(&line[..line.len() - 1], body.as_slice());
    }

    #[test]
    fn capath_loads_pem_crt_and_cer_files() {
        let dir = std::env::temp_dir().join(format!("pgpp-capath-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        for f in [
            "a.pem", "b.crt", "c.cer", "d.txt", "e.der", "pem", "G.PEM", "h.Crt", "i.CER", "j.PEMX",
        ] {
            std::fs::write(dir.join(f), "x").unwrap();
        }
        std::fs::create_dir(dir.join("f.pem")).unwrap();
        let names: Vec<String> = capath_files(&dir)
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        // extensions compared without regard to case
        assert_eq!(
            names,
            ["G.PEM", "a.pem", "b.crt", "c.cer", "h.Crt", "i.CER"]
        );
        assert_eq!(capath_patterns(), "*.pem / *.crt / *.cer");
        let _ = std::fs::remove_dir_all(&dir);
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
