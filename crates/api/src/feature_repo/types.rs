//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ApiError, ApiResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub fields: Vec<(String, String)>,
    pub sha256: Vec<ReleaseChecksum>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseChecksum {
    pub sha256: String,
    pub size: u64,
    pub path: String,
}

impl Release {
    pub fn parse(bytes: &[u8]) -> ApiResult<Self> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ApiError::BadRequest("Release is not valid UTF-8".into()))?;
        let mut fields = Vec::new();
        let mut sha256 = Vec::new();
        let mut in_sha256 = false;

        for line in text.lines() {
            if in_sha256 && (line.starts_with(' ') || line.starts_with('\t')) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() != 3
                    || parts[0].len() != 64
                    || !parts[0].bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(ApiError::BadRequest("invalid Release SHA256 entry".into()));
                }
                sha256.push(ReleaseChecksum {
                    sha256: parts[0].to_ascii_lowercase(),
                    size: parts[1]
                        .parse()
                        .map_err(|_| ApiError::BadRequest("invalid Release SHA256 size".into()))?,
                    path: parts[2].to_string(),
                });
                continue;
            }

            in_sha256 = false;
            if line.trim().is_empty() {
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(ApiError::BadRequest("invalid Release field".into()));
            };
            if name == "SHA256" {
                in_sha256 = true;
            } else {
                fields.push((name.to_string(), value.trim().to_string()));
            }
        }

        if sha256.is_empty() {
            return Err(ApiError::BadRequest(
                "Release does not contain SHA256 entries".into(),
            ));
        }
        Ok(Self { fields, sha256 })
    }

    pub fn checksum(&self, path: &str) -> Option<&ReleaseChecksum> {
        self.sha256.iter().find(|entry| entry.path == path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturesIndex {
    #[serde(default)]
    pub schema_version: Option<u32>,
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub features: Vec<FeatureIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureIndexEntry {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub latest: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default, alias = "manifest_path", alias = "feature_json")]
    pub manifest: Option<String>,
    #[serde(default)]
    pub versions: Vec<FeatureVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVersion {
    pub version: String,
    #[serde(alias = "path", alias = "feature_json")]
    pub manifest: String,
}

impl FeatureIndexEntry {
    pub fn resolve_version(&self, requested: Option<&str>) -> ApiResult<FeatureVersion> {
        if let Some(version) = requested {
            if let Some(entry) = self.versions.iter().find(|entry| entry.version == version) {
                return Ok(entry.clone());
            }
            if self.version.as_deref() == Some(version) {
                if let Some(manifest) = &self.manifest {
                    return Ok(FeatureVersion {
                        version: version.to_string(),
                        manifest: manifest.clone(),
                    });
                }
            }
            return Err(ApiError::BadRequest(format!(
                "feature {} has no version {version}",
                self.id
            )));
        }

        let selected = self
            .latest
            .as_deref()
            .or(self.version.as_deref())
            .or_else(|| self.versions.first().map(|entry| entry.version.as_str()))
            .ok_or_else(|| {
                ApiError::BadRequest(format!("feature {} has no published version", self.id))
            })?;
        self.resolve_version(Some(selected))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureManifest {
    pub id: String,
    pub version: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub commands: Vec<FeatureCommand>,
    #[serde(default)]
    pub artifacts: Vec<FeatureArtifact>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureCommand {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default = "default_risk_level")]
    pub risk_level: String,
}

fn default_risk_level() -> String {
    "high".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureArtifact {
    pub os: String,
    pub arch: String,
    pub filename: String,
    pub sha256: String,
    #[serde(default, alias = "path")]
    pub url: Option<String>,
    /// Optional canonical self-update signature (base64) for fleet agents that
    /// only verify the legacy `v1\\n{kind}\\n{version}\\n{sha256}\\n{sha256}` message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_sha256_section() {
        let release = Release::parse(
            b"Origin: Hecate\nSHA256:\n abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd 42 features.json\n",
        )
        .expect("valid Release");
        let checksum = release.checksum("features.json").expect("features entry");
        assert_eq!(checksum.size, 42);
        assert_eq!(
            checksum.sha256,
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        );
    }

    #[test]
    fn rejects_release_without_checksums() {
        assert!(Release::parse(b"Origin: Hecate\n").is_err());
    }
}
