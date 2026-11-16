//! Browser impersonation.
//!
//! Makes requests look like they come from a real browser: the TLS
//! `ClientHello`, the HTTP/2 settings and pseudo-header order, and the default
//! request headers all come from the browser fingerprints of
//! [impit](https://github.com/apify/impit).
//!
//! This relies on the patched `rustls`, `h2`, `hyper-util` and `tower-http`
//! crates that impit uses; see the `[patch.crates-io]` section of the
//! workspace `Cargo.toml`.

// The TLS configuration is adapted from impit's `tls` module, which impit does
// not export. impit is licensed under the Apache License 2.0.

use std::{fmt, str::FromStr, sync::Arc};

use http::{HeaderMap, HeaderName, HeaderValue, header};
use impit::fingerprint::{BrowserFingerprint, database};
use reqwest::tls;
use rustls::{
    ClientConfig, SupportedProtocolVersion,
    client::{EchGreaseConfig, EchMode, Resumption, Tls12Resumption, danger::NoVerifier},
    crypto::{CryptoProvider, aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128, hpke::Hpke},
};
use rustls_platform_verifier::Verifier;

use crate::{ErrorKind, Result};

/// Environment variable from which the patched `h2` crate reads the HTTP/2
/// pseudo-header order.
///
/// `h2` reads it for every request, so it has to be set before any threads
/// start, e.g. at the top of `main`. See [`Impersonate::h2_pseudo_header_order`].
pub const H2_PSEUDO_HEADER_ORDER_ENV: &str = "IMPIT_H2_PSEUDOHEADERS_ORDER";

/// A browser profile name and the function that returns its fingerprint.
type Profile = (&'static str, fn() -> BrowserFingerprint);

/// Browser profiles that can be impersonated, by name.
///
/// `chrome` and `firefox` are aliases for the newest profile of that browser.
const PROFILES: &[Profile] = &[
    ("chrome", database::chrome_157::fingerprint),
    ("firefox", database::firefox_158::fingerprint),
    ("chrome_100", database::chrome_100::fingerprint),
    ("chrome_101", database::chrome_101::fingerprint),
    ("chrome_104", database::chrome_104::fingerprint),
    ("chrome_107", database::chrome_107::fingerprint),
    ("chrome_110", database::chrome_110::fingerprint),
    ("chrome_116", database::chrome_116::fingerprint),
    ("chrome_124", database::chrome_124::fingerprint),
    ("chrome_125", database::chrome_125::fingerprint),
    ("chrome_131", database::chrome_131::fingerprint),
    ("chrome_133", database::chrome_133::fingerprint),
    ("chrome_136", database::chrome_136::fingerprint),
    ("chrome_142", database::chrome_142::fingerprint),
    ("chrome_151", database::chrome_151::fingerprint),
    ("chrome_155", database::chrome_155::fingerprint),
    ("chrome_156", database::chrome_156::fingerprint),
    ("chrome_157", database::chrome_157::fingerprint),
    ("firefox_128", database::firefox_128::fingerprint),
    ("firefox_133", database::firefox_133::fingerprint),
    ("firefox_135", database::firefox_135::fingerprint),
    ("firefox_144", database::firefox_144::fingerprint),
    ("firefox_158", database::firefox_158::fingerprint),
    ("ios_18", database::ios_18::fingerprint),
    ("okhttp3", database::okhttp3::fingerprint),
    ("okhttp4", database::okhttp4::fingerprint),
    ("okhttp5", database::okhttp5::fingerprint),
];

/// Names of the browser profiles accepted by [`Impersonate::from_str`].
pub fn profile_names() -> impl Iterator<Item = &'static str> {
    PROFILES.iter().map(|(name, _)| *name)
}

/// A browser to impersonate.
///
/// Parse one from a profile name (see [`profile_names`]) and pass it to
/// [`ClientBuilder::impersonate`](crate::ClientBuilder).
#[derive(Clone)]
pub struct Impersonate {
    name: &'static str,
    fingerprint: BrowserFingerprint,
}

impl fmt::Debug for Impersonate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The fingerprint itself is long and not useful in logs.
        f.debug_tuple("Impersonate").field(&self.name).finish()
    }
}

impl FromStr for Impersonate {
    type Err = ErrorKind;

    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        PROFILES
            .iter()
            .find(|(profile, _)| *profile == name)
            .map(|(name, fingerprint)| Self {
                name,
                fingerprint: fingerprint(),
            })
            .ok_or_else(|| {
                ErrorKind::InvalidImpersonation(format!(
                    "unknown browser profile `{name}`, expected one of: {}",
                    profile_names().collect::<Vec<_>>().join(", ")
                ))
            })
    }
}

impl Impersonate {
    /// Name of the browser profile, e.g. `firefox_158`.
    #[must_use]
    pub const fn name(&self) -> &str {
        self.name
    }

    /// The browser's `User-Agent` header.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.fingerprint
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(header::USER_AGENT.as_str()))
            .map(|(_, value)| value.as_str())
    }

    /// The browser's HTTP/2 pseudo-header order, as the value for
    /// [`H2_PSEUDO_HEADER_ORDER_ENV`].
    ///
    /// The patched `h2` crate only reads it from that environment variable.
    /// Without it, HTTP/2 requests use the default pseudo-header order.
    #[must_use]
    pub fn h2_pseudo_header_order(&self) -> Option<String> {
        let order = &self.fingerprint.http2.pseudo_header_order;
        (!order.is_empty()).then(|| order.join(","))
    }

    /// The browser's default request headers, in the browser's order.
    pub(crate) fn headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        for (name, value) in &self.fingerprint.headers {
            let name = HeaderName::try_from(name.as_str()).map_err(|e| {
                ErrorKind::InvalidImpersonation(format!("invalid header name `{name}`: {e}"))
            })?;
            headers.insert(name, HeaderValue::try_from(value.as_str())?);
        }
        Ok(headers)
    }

    /// Applies the browser's TLS and HTTP fingerprint to `builder`.
    ///
    /// reqwest ignores `min_tls_version` and `danger_accept_invalid_certs` once
    /// a TLS config is given, so both are applied to that config here.
    pub(crate) fn configure(
        &self,
        mut builder: reqwest::ClientBuilder,
        allow_insecure: bool,
        min_tls_version: Option<tls::Version>,
    ) -> Result<reqwest::ClientBuilder> {
        let http2 = &self.fingerprint.http2;
        if let Some(size) = http2.initial_stream_window_size {
            builder = builder.http2_initial_stream_window_size(size);
        }
        if let Some(size) = http2.initial_connection_window_size {
            builder = builder.http2_initial_connection_window_size(size);
        }
        if let Some(size) = http2.max_header_list_size {
            builder = builder.http2_max_header_list_size(size);
        }
        if let Some(size) = http2.header_table_size {
            builder = builder.http2_header_table_size(size);
        }
        if let Some(max) = http2.max_concurrent_streams {
            builder = builder.http2_max_concurrent_streams(max);
        }

        Ok(builder
            // Browsers send HTTP/1.1 header names in title case.
            .http1_title_case_headers()
            .use_preconfigured_tls(self.tls_config(allow_insecure, min_tls_version)?))
    }

    fn tls_config(
        &self,
        allow_insecure: bool,
        min_tls_version: Option<tls::Version>,
    ) -> Result<ClientConfig> {
        let fingerprint = &self.fingerprint.tls;
        let rustls_fingerprint = fingerprint.to_rustls_fingerprint();
        let tls13_only = min_tls_version == Some(tls::Version::TLS_1_3);

        let provider: Arc<CryptoProvider> = CryptoProvider::builder()
            .with_tls_fingerprint(rustls_fingerprint.clone())
            .build()
            .into();
        let verifier = Arc::new(
            Verifier::new_with_extra_roots(
                webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned(),
                provider.clone(),
            )
            .map_err(|e| self.error(format!("cannot create certificate verifier: {e}")))?,
        );

        let mut config = if fingerprint.ech_config.is_some() {
            // ECH needs TLS 1.3, so `min_tls_version` is always met.
            let ech_mode = ech_grease_mode()
                .map_err(|e| self.error(format!("cannot set up ECH GREASE: {e}")))?;
            ClientConfig::builder_with_provider(provider)
                .with_ech(ech_mode)
                .map_err(|e| self.error(e))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_tls_fingerprint(rustls_fingerprint)
                .with_no_client_auth()
        } else {
            let versions: &[&SupportedProtocolVersion] =
                match (fingerprint.extensions.supported_versions, tls13_only) {
                    (true, false) => rustls::DEFAULT_VERSIONS,
                    (true, true) => &[&rustls::version::TLS13],
                    (false, false) => &[&rustls::version::TLS12],
                    (false, true) => {
                        return Err(self
                            .error("the browser only supports TLS 1.2, but TLS 1.3 is required"));
                    }
                };
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(versions)
                .map_err(|e| self.error(e))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_tls_fingerprint(rustls_fingerprint)
                .with_no_client_auth()
        };

        config
            .alpn_protocols
            .clone_from(&fingerprint.alpn_protocols);

        if !fingerprint.extensions.session_ticket {
            // Without session tickets, browsers still resume TLS 1.2 sessions by ID.
            config.resumption = Resumption::in_memory_sessions(256)
                .tls12_resumption(Tls12Resumption::SessionIdOnly);
        }

        if allow_insecure {
            // The ClientHello advertises the verifier's signature schemes, so keep the browser's.
            let schemes = config
                .crypto_provider()
                .signature_verification_algorithms
                .supported_schemes();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier::new(schemes)));
        }

        Ok(config)
    }

    fn error(&self, message: impl fmt::Display) -> ErrorKind {
        ErrorKind::InvalidImpersonation(format!("{}: {message}", self.name))
    }
}

/// ECH GREASE, which browsers send when they have no ECH config for the server.
fn ech_grease_mode() -> std::result::Result<EchMode, rustls::Error> {
    let suite: &'static dyn Hpke = DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (public_key, _) = suite.generate_key_pair()?;
    Ok(EchGreaseConfig::new(suite, public_key).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_profiles() {
        for name in profile_names() {
            let impersonate: Impersonate = name.parse().unwrap();
            assert_eq!(impersonate.name(), name);
            assert!(
                impersonate.user_agent().is_some(),
                "{name} has no user agent"
            );
            impersonate.headers().unwrap();
            impersonate.tls_config(false, None).unwrap();
        }
        assert!(matches!(
            "netscape".parse::<Impersonate>(),
            Err(ErrorKind::InvalidImpersonation(_))
        ));
    }

    #[test]
    fn test_aliases_use_the_newest_profiles() {
        let firefox: Impersonate = "firefox".parse().unwrap();
        assert!(firefox.user_agent().unwrap().contains("Firefox/158.0"));
        let chrome: Impersonate = "chrome".parse().unwrap();
        assert!(chrome.user_agent().unwrap().contains("Chrome/157."));
    }

    #[test]
    fn test_min_tls_version() {
        let firefox: Impersonate = "firefox".parse().unwrap();
        firefox
            .tls_config(false, Some(tls::Version::TLS_1_3))
            .unwrap();
        firefox
            .tls_config(true, Some(tls::Version::TLS_1_2))
            .unwrap();
    }
}
