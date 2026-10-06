//! OpenAI-only network egress policy.
//!
//! This build may only open network connections to OpenAI-operated hosts and
//! to the local machine. Every reqwest client must be created through
//! [`client_builder`] (or [`blocking_client_builder`]); `clippy.toml` rejects
//! the raw constructors elsewhere. Hand-rolled sockets must call
//! [`check_host`] before resolving or connecting.
//!
//! reqwest clients get two independent layers:
//!
//! 1. A [`reqwest::Proxy::custom`] hook sees the destination of every new
//!    connection, including redirects and IP literals, regardless of any
//!    configured proxy. Disallowed destinations are routed to a sentinel proxy
//!    that never resolves, so the request fails before any byte leaves the
//!    machine.
//! 2. A DNS resolver that only resolves allowed hosts and the proxies taken
//!    from the standard `*_PROXY` environment variables.
//!
//! The policy is compiled in. There is deliberately no runtime override.

use std::{
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use url::Url;

/// Registrable domains whose hosts (and subdomains) may be contacted.
pub const ALLOWED_DOMAINS: &[&str] = &["openai.com", "chatgpt.com", "oaistatic.com"];

/// Never resolvable (RFC 6761); the resolver below also refuses it explicitly.
const BLOCKED_PROXY_HOST: &str = "nanocodex-egress-blocked.invalid";

/// A connection refused by the OpenAI-only egress policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blocked {
    host: Option<String>,
}

impl Blocked {
    fn host(host: &str) -> Self {
        Self {
            host: Some(host.to_owned()),
        }
    }

    /// The refused host, when it is known at the point of refusal.
    #[must_use]
    pub fn blocked_host(&self) -> Option<&str> {
        self.host.as_deref()
    }
}

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Some(host) => write!(f, "network access to `{host}` is blocked")?,
            None => f.write_str("network access to a non-OpenAI host is blocked")?,
        }
        f.write_str(": this build only connects to OpenAI hosts (")?;
        for (index, domain) in ALLOWED_DOMAINS.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            f.write_str(domain)?;
        }
        f.write_str(") and loopback")
    }
}

impl Error for Blocked {}

fn normalize(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// Whether `host` (a DNS name or IP literal) may be contacted.
#[must_use]
pub fn is_allowed_host(host: &str) -> bool {
    let host = normalize(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    host == "localhost"
        || ALLOWED_DOMAINS.iter().any(|domain| {
            host == *domain
                || host
                    .strip_suffix(domain)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
}

/// Refuses hosts outside the allowlist.
///
/// # Errors
///
/// Returns [`Blocked`] when `host` is not an allowed host.
pub fn check_host(host: &str) -> Result<(), Blocked> {
    if is_allowed_host(host) {
        Ok(())
    } else {
        tracing::warn!(target: "nanocodex_net_allowlist", host, "blocked connection to a non-OpenAI host");
        Err(Blocked::host(host))
    }
}

/// Refuses URLs whose host is outside the allowlist, or that have no host.
///
/// # Errors
///
/// Returns [`Blocked`] when the URL has no host or its host is not allowed.
pub fn check_url(url: &Url) -> Result<(), Blocked> {
    match url.host_str() {
        Some(host) => check_host(host),
        None => Err(Blocked::host(url.scheme())),
    }
}

/// An async reqwest client builder that enforces the allowlist.
///
/// Do not call `no_proxy`, `dns_resolver`, `resolve` or `resolve_to_addrs` on
/// the result: each would remove a layer of enforcement.
#[must_use]
#[allow(clippy::disallowed_methods)]
pub fn client_builder() -> reqwest::ClientBuilder {
    let proxies = EnvProxies::from_env();
    let mut builder = reqwest::Client::builder()
        .dns_resolver(Arc::new(GuardedResolver {
            proxy_hosts: proxies.hosts.into(),
        }))
        .proxy(guard_proxy());
    for proxy in proxies.proxies {
        builder = builder.proxy(proxy);
    }
    builder
}

/// A default async client that enforces the allowlist.
///
/// # Panics
///
/// Panics when the TLS backend cannot be initialized, like `reqwest::Client::new`.
pub fn client() -> reqwest::Client {
    client_builder()
        .build()
        .expect("TLS backend and resolver configuration are valid")
}

/// A blocking reqwest client builder that enforces the allowlist.
#[cfg(feature = "blocking")]
#[must_use]
#[allow(clippy::disallowed_methods)]
pub fn blocking_client_builder() -> reqwest::blocking::ClientBuilder {
    let proxies = EnvProxies::from_env();
    let mut builder = reqwest::blocking::Client::builder()
        .dns_resolver(Arc::new(GuardedResolver {
            proxy_hosts: proxies.hosts.into(),
        }))
        .proxy(guard_proxy());
    for proxy in proxies.proxies {
        builder = builder.proxy(proxy);
    }
    builder
}

/// A default blocking client that enforces the allowlist.
///
/// # Panics
///
/// Panics when the TLS backend cannot be initialized, like
/// `reqwest::blocking::Client::new`.
#[cfg(feature = "blocking")]
pub fn blocking_client() -> reqwest::blocking::Client {
    blocking_client_builder()
        .build()
        .expect("TLS backend and resolver configuration are valid")
}

fn guard_proxy() -> reqwest::Proxy {
    reqwest::Proxy::custom(|url: &Url| {
        if url.host_str().is_some_and(is_allowed_host) {
            return None;
        }
        tracing::warn!(
            target: "nanocodex_net_allowlist",
            host = url.host_str().unwrap_or_default(),
            "blocked request to a non-OpenAI host"
        );
        Some(format!("http://{BLOCKED_PROXY_HOST}"))
    })
}

struct GuardedResolver {
    proxy_hosts: Arc<[String]>,
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let normalized = normalize(&host);
        let permitted = normalized != BLOCKED_PROXY_HOST
            && (is_allowed_host(&normalized) || self.proxy_hosts.contains(&normalized));
        Box::pin(async move {
            if !permitted {
                let blocked = if normalized == BLOCKED_PROXY_HOST {
                    Blocked { host: None }
                } else {
                    Blocked::host(&host)
                };
                return Err(Box::new(blocked) as Box<dyn Error + Send + Sync>);
            }
            let addresses: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

/// Explicit replacements for reqwest's system proxy, which is disabled as soon
/// as the guard proxy is added. Only the environment variables are honored.
struct EnvProxies {
    proxies: Vec<reqwest::Proxy>,
    hosts: Vec<String>,
}

impl EnvProxies {
    fn from_env() -> Self {
        let mut this = Self {
            proxies: Vec::new(),
            hosts: Vec::new(),
        };
        for (upper, lower, scheme) in [
            ("HTTPS_PROXY", "https_proxy", ProxyScheme::Https),
            ("HTTP_PROXY", "http_proxy", ProxyScheme::Http),
            ("ALL_PROXY", "all_proxy", ProxyScheme::All),
        ] {
            let Some(value) = std::env::var(upper)
                .or_else(|_| std::env::var(lower))
                .ok()
                .filter(|value| !value.trim().is_empty())
            else {
                continue;
            };
            let proxy = match scheme {
                ProxyScheme::Https => reqwest::Proxy::https(value.as_str()),
                ProxyScheme::Http => reqwest::Proxy::http(value.as_str()),
                ProxyScheme::All => reqwest::Proxy::all(value.as_str()),
            };
            match proxy {
                Ok(proxy) => {
                    this.proxies
                        .push(proxy.no_proxy(reqwest::NoProxy::from_env()));
                    if let Some(host) = proxy_host(&value) {
                        this.hosts.push(host);
                    }
                }
                Err(error) => {
                    tracing::warn!(target: "nanocodex_net_allowlist", variable = upper, %error, "ignoring invalid proxy");
                }
            }
        }
        this
    }
}

#[derive(Clone, Copy)]
enum ProxyScheme {
    Https,
    Http,
    All,
}

fn proxy_host(value: &str) -> Option<String> {
    let url = Url::parse(value)
        .ok()
        .filter(|url| url.has_host())
        .or_else(|| Url::parse(&format!("http://{value}")).ok())?;
    url.host_str().map(normalize)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };

    use super::*;

    #[test]
    fn allows_only_openai_domains_and_loopback() {
        for host in [
            "openai.com",
            "api.openai.com",
            "API.OpenAI.com.",
            "auth.openai.com",
            "chatgpt.com",
            "persistent.oaistatic.com",
            "localhost",
            "127.0.0.1",
            "127.8.9.10",
            "::1",
            "[::1]",
        ] {
            assert!(is_allowed_host(host), "{host} should be allowed");
        }
        for host in [
            "example.com",
            "evilopenai.com",
            "openai.com.evil.example",
            "chatgpt.co",
            "mercator.sh",
            "api.github.com",
            "huggingface.co",
            "nanocodex.gakonst.workers.dev",
            "192.0.2.1",
            "10.0.0.1",
            "::ffff:127.0.0.1",
            "",
            BLOCKED_PROXY_HOST,
        ] {
            assert!(!is_allowed_host(host), "{host} should be blocked");
        }
    }

    #[test]
    fn check_url_rejects_hostless_urls() {
        assert!(check_url(&Url::parse("wss://api.openai.com/v1/responses").unwrap()).is_ok());
        assert!(check_url(&Url::parse("wss://mcp.tempo.xyz").unwrap()).is_err());
        assert!(check_url(&Url::parse("data:text/plain,hi").unwrap()).is_err());
    }

    fn assert_blocked(error: &reqwest::Error) {
        let mut source: Option<&dyn Error> = Some(error);
        while let Some(current) = source {
            if current.downcast_ref::<Blocked>().is_some() {
                return;
            }
            source = current.source();
        }
        panic!("request failed without the egress policy error: {error:?}");
    }

    fn install_crypto_provider() {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            drop(rustls::crypto::ring::default_provider().install_default());
        }
    }

    async fn blocked(url: &str) {
        install_crypto_provider();
        let error = client_builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .get(url)
            .send()
            .await
            .expect_err("request to a non-OpenAI host must fail");
        assert_blocked(&error);
    }

    #[tokio::test]
    async fn blocks_disallowed_hostnames_and_ip_literals() {
        blocked("https://example.com/").await;
        blocked("http://mercator.sh/mcp").await;
        blocked("http://192.0.2.1:9/").await;
        blocked("http://[2001:db8::1]:9/").await;
    }

    fn serve_once(response: String) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 4096];
            let _ = stream.read(&mut buffer);
            stream.write_all(response.as_bytes()).unwrap();
        });
        port
    }

    #[tokio::test]
    async fn allows_loopback_but_blocks_redirects_off_the_allowlist() {
        install_crypto_provider();
        let port = serve_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok".into(),
        );
        let body = client()
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "ok");

        let port = serve_once(
            "HTTP/1.1 302 Found\r\nlocation: http://example.com/\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".into(),
        );
        blocked(&format!("http://127.0.0.1:{port}/")).await;
    }
}
