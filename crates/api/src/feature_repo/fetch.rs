//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hecate_protocol::remote_download_policy;
use reqwest::redirect::Policy;
use url::Url;

use crate::error::{ApiError, ApiResult};

pub const METADATA_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const ARTIFACT_MAX_BYTES: usize = 512 * 1024 * 1024;

pub fn build_client() -> ApiResult<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|error| ApiError::Internal(error.into()))
}

pub fn parse_public_https_url(raw: &str) -> ApiResult<Url> {
    let url = Url::parse(raw)
        .map_err(|error| ApiError::BadRequest(format!("invalid repository URL: {error}")))?;
    if url.scheme() != "https" {
        return Err(ApiError::BadRequest(
            "repository URLs must use HTTPS".into(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ApiError::BadRequest(
            "repository URLs must not contain credentials".into(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("repository URL has no host".into()))?;
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return Err(ApiError::BadRequest(
            "repository URL resolves to a blocked host".into(),
        ));
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) => reject_blocked_ip(IpAddr::V4(ip))?,
        Some(url::Host::Ipv6(ip)) => reject_blocked_ip(IpAddr::V6(ip))?,
        Some(url::Host::Domain(_)) | None => {
            if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
                reject_blocked_ip(ip)?;
            }
        }
    }
    Ok(url)
}

pub fn join_url(base: &str, path: &str) -> ApiResult<Url> {
    let base = parse_public_https_url(base)?;
    let base = if base.path().ends_with('/') {
        base
    } else {
        Url::parse(&format!("{}/", base.as_str().trim_end_matches('/')))
            .map_err(|error| ApiError::BadRequest(format!("invalid repository URL: {error}")))?
    };
    let joined = base
        .join(path)
        .map_err(|error| ApiError::BadRequest(format!("invalid repository path: {error}")))?;
    parse_public_https_url(joined.as_str())
}

pub async fn fetch_bytes(
    _client: &reqwest::Client,
    url: Url,
    max_bytes: usize,
) -> ApiResult<Vec<u8>> {
    let pinned = pin_repository_host(&url).await?;
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120));
    if host_is_name(&pinned.host) {
        builder = builder.resolve(&pinned.host, pinned.addr);
    }
    let client = builder
        .build()
        .map_err(|error| ApiError::Internal(error.into()))?;
    let mut response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|error| ApiError::BadRequest(format!("failed to fetch {url}: {error}")))?;
    if !response.status().is_success() {
        return Err(ApiError::BadRequest(format!(
            "failed to fetch {url}: HTTP {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(ApiError::BadRequest(format!(
            "repository response exceeds {max_bytes} bytes"
        )));
    }
    let mut bytes =
        Vec::with_capacity(response.content_length().unwrap_or(0).min(max_bytes as u64) as usize);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ApiError::BadRequest(format!("failed to read {url}: {error}")))?
    {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ApiError::BadRequest(format!(
                "repository response exceeds {max_bytes} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

struct PinnedHost {
    host: String,
    addr: SocketAddr,
}

fn host_is_name(host: &str) -> bool {
    host.parse::<IpAddr>().is_err()
}

async fn pin_repository_host(url: &Url) -> ApiResult<PinnedHost> {
    let host = url
        .host_str()
        .ok_or_else(|| ApiError::BadRequest("repository URL has no host".into()))?
        .to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let addr: SocketAddr = if let Ok(ip) = host.parse::<IpAddr>() {
        reject_blocked_ip(ip)?;
        SocketAddr::new(ip, port)
    } else {
        let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|error| {
                ApiError::BadRequest(format!("cannot resolve repository host: {error}"))
            })?
            .collect();
        if addresses.is_empty() {
            return Err(ApiError::BadRequest(
                "repository host resolved to no addresses".into(),
            ));
        }
        let mut chosen = None;
        for address in addresses {
            reject_blocked_ip(address.ip())?;
            chosen.get_or_insert(address);
        }
        chosen.ok_or_else(|| {
            ApiError::BadRequest("repository host resolved to no addresses".into())
        })?
    };

    Ok(PinnedHost { host, addr })
}

fn reject_blocked_ip(ip: IpAddr) -> ApiResult<()> {
    if remote_download_policy::is_blocked_ip(ip) {
        Err(ApiError::BadRequest(
            "repository URL resolves to a private or reserved address".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_and_private_urls() {
        assert!(parse_public_https_url("http://example.com/features.json").is_err());
        assert!(parse_public_https_url("https://127.0.0.1/features.json").is_err());
        assert!(parse_public_https_url("https://10.0.0.1/features.json").is_err());
        assert!(parse_public_https_url("https://169.254.169.254/latest/meta-data").is_err());
        assert!(parse_public_https_url("https://[::1]/features.json").is_err());
        assert!(parse_public_https_url("https://[::ffff:127.0.0.1]/features.json").is_err());
        assert!(parse_public_https_url("https://example.com/features.json").is_ok());
        assert!(parse_public_https_url("https://100.64.0.1/features.json").is_err());
    }
}
