//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RemoteDownloadPolicyError {
    #[error("url must not be empty")]
    EmptyUrl,
    #[error("only https URLs are allowed")]
    SchemeNotAllowed,
    #[error("url host is not allowed: {host}")]
    HostNotAllowed { host: String },
    #[error("invalid url: {0}")]
    InvalidUrl(String),
}

/// Validates remote.download URLs (HTTPS only, blocks private/reserved targets).
pub fn check_remote_download_url(raw: &str) -> Result<(), RemoteDownloadPolicyError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RemoteDownloadPolicyError::EmptyUrl);
    }

    let parsed = url::Url::parse(trimmed)
        .map_err(|error| RemoteDownloadPolicyError::InvalidUrl(error.to_string()))?;

    if parsed.scheme() != "https" {
        return Err(RemoteDownloadPolicyError::SchemeNotAllowed);
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| RemoteDownloadPolicyError::InvalidUrl("missing host".into()))?;

    if is_blocked_host(host) {
        return Err(RemoteDownloadPolicyError::HostNotAllowed {
            host: host.to_string(),
        });
    }

    Ok(())
}

fn is_blocked_host(host: &str) -> bool {
    let host_lower = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host_lower == "localhost" || host_lower.ends_with(".localhost") {
        return true;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(ip);
    }

    false
}

pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => is_blocked_ipv6(v6),
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || ip.octets()[0] == 0
        || ip.octets()[0] >= 240
        // CGNAT / shared address space (RFC 6598).
        || (ip.octets()[0] == 100 && ip.octets()[1] & 0b1100_0000 == 64)
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast()
        || ip.segments()[0] & 0xff00 == 0xfe80
        || (ip.segments()[0] == 0x64 && ip.segments()[1] == 0xff9b)
        // IPv6 documentation (RFC 3849).
        || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0xdb8)
        // Teredo (RFC 4380) can embed arbitrary IPv4.
        || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0)
    {
        return true;
    }
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(mapped);
    }
    if ip.segments()[0] == 0x2002 {
        let octets = ip.octets();
        return is_blocked_ipv4(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_public_https_url() {
        check_remote_download_url("https://example.com/file.tar.gz").unwrap();
    }

    #[test]
    fn rejects_http_scheme() {
        assert_eq!(
            check_remote_download_url("http://example.com/x"),
            Err(RemoteDownloadPolicyError::SchemeNotAllowed)
        );
    }

    #[test]
    fn rejects_localhost() {
        assert!(matches!(
            check_remote_download_url("https://localhost/x"),
            Err(RemoteDownloadPolicyError::HostNotAllowed { .. })
        ));
    }

    #[test]
    fn rejects_private_ipv4_literal() {
        assert!(matches!(
            check_remote_download_url("https://192.168.1.1/x"),
            Err(RemoteDownloadPolicyError::HostNotAllowed { .. })
        ));
    }

    #[test]
    fn rejects_ipv4_mapped_loopback() {
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip("64:ff9b::c000:201".parse().unwrap()));
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("2001:db8::1".parse().unwrap()));
        assert!(is_blocked_ip("2001::1".parse().unwrap()));
        assert!(is_blocked_ip("2002:7f00:1::1".parse().unwrap()));
    }
}
