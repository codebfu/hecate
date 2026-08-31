//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

//! Canonical agent release-artifact URL paths shared by API, Propylaea, and agents.

pub const RELEASE_ARTIFACT_PATH_PREFIX: &str = "/api/v1/agent/releases";

/// Feature / helper components that ship signed release artifacts.
pub const RELEASE_COMPONENTS: &[&str] = &["agent", "desktop", "proxmox"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseComponent {
    Agent,
    Desktop,
    Proxmox,
}

impl ReleaseComponent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Desktop => "desktop",
            Self::Proxmox => "proxmox",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "agent" => Some(Self::Agent),
            "desktop" => Some(Self::Desktop),
            "proxmox" => Some(Self::Proxmox),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseArtifactRoute {
    pub version: String,
    pub component: ReleaseComponent,
}

pub fn validate_release_path_segment(kind: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.'))
    {
        return Err(format!("invalid {kind}"));
    }
    Ok(())
}

/// Canonical path: `/api/v1/agent/releases/{version}/artifact/{component}`.
pub fn release_artifact_api_path(version: &str, component: ReleaseComponent) -> String {
    format!(
        "{RELEASE_ARTIFACT_PATH_PREFIX}/{version}/artifact/{}",
        component.as_str()
    )
}

pub fn parse_release_artifact_path(path: &str) -> Option<ReleaseArtifactRoute> {
    let path = path.trim();
    if path.contains('\\') || path.contains("..") || path.contains("//") || path.contains("/./") {
        return None;
    }
    let rest = path.strip_prefix(RELEASE_ARTIFACT_PATH_PREFIX)?;
    let rest = rest.strip_prefix('/')?;
    let segments: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        [version, "artifact", component] => {
            validate_release_path_segment("version", version).ok()?;
            let component = ReleaseComponent::parse(component)?;
            Some(ReleaseArtifactRoute {
                version: (*version).to_string(),
                component,
            })
        }
        // Legacy aliases kept for one release cycle.
        [version, "artifact"] => {
            validate_release_path_segment("version", version).ok()?;
            Some(ReleaseArtifactRoute {
                version: (*version).to_string(),
                component: ReleaseComponent::Agent,
            })
        }
        [version, "desktop-artifact"] => {
            validate_release_path_segment("version", version).ok()?;
            Some(ReleaseArtifactRoute {
                version: (*version).to_string(),
                component: ReleaseComponent::Desktop,
            })
        }
        [version, "proxmox-artifact"] => {
            validate_release_path_segment("version", version).ok()?;
            Some(ReleaseArtifactRoute {
                version: (*version).to_string(),
                component: ReleaseComponent::Proxmox,
            })
        }
        _ => None,
    }
}

pub fn is_release_artifact_path(path: &str) -> bool {
    parse_release_artifact_path(path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_every_component() {
        for name in RELEASE_COMPONENTS {
            let component = ReleaseComponent::parse(name).expect("known component");
            let path = release_artifact_api_path("1.2.3", component);
            let parsed = parse_release_artifact_path(&path).expect("parse canonical");
            assert_eq!(parsed.version, "1.2.3");
            assert_eq!(parsed.component, component);
            assert!(is_release_artifact_path(&path));
        }
    }

    #[test]
    fn legacy_aliases() {
        let agent = parse_release_artifact_path("/api/v1/agent/releases/1.0.0/artifact").unwrap();
        assert_eq!(agent.component, ReleaseComponent::Agent);
        let desktop =
            parse_release_artifact_path("/api/v1/agent/releases/1.0.0/desktop-artifact").unwrap();
        assert_eq!(desktop.component, ReleaseComponent::Desktop);
        let proxmox =
            parse_release_artifact_path("/api/v1/agent/releases/1.0.0/proxmox-artifact").unwrap();
        assert_eq!(proxmox.component, ReleaseComponent::Proxmox);
    }

    #[test]
    fn rejects_traversal_and_unknown() {
        assert!(parse_release_artifact_path(
            "/api/v1/agent/releases/../etc/artifact/agent"
        )
        .is_none());
        assert!(parse_release_artifact_path("/api/v1/agent/releases/1.0.0/artifact/evil").is_none());
        assert!(parse_release_artifact_path("/api/v1/agent/releases/1.0.0/other").is_none());
    }
}
