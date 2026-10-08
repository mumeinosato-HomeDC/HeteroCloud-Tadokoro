//! The strict VM specification HeteroCloud forwards unchanged to this provider.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const MAX_NAME_BYTES: usize = 120;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmSpec {
    pub region: String,
    /// Image name that maps to a template on the configured node.
    pub image: String,
    pub cpu_cores: u32,
    pub memory_mib: u32,
    pub disk_gib: u32,
    /// OpenSSH public keys installed for `username` through cloud-init.
    pub ssh_authorized_keys: Vec<String>,
    #[serde(default = "default_username")]
    pub username: String,
    /// Keep the VM defined but powered off.
    #[serde(default)]
    pub stopped: bool,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

fn default_username() -> String {
    "ubuntu".into()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SpecError {
    #[error("{0}")]
    Invalid(String),
}

fn invalid<T>(message: impl Into<String>) -> Result<T, SpecError> {
    Err(SpecError::Invalid(message.into()))
}

impl VmSpec {
    pub fn validate(&self, region: &str, images: &BTreeMap<String, u32>) -> Result<(), SpecError> {
        if self.region != region {
            return invalid(format!("region must be {region}"));
        }
        if !images.contains_key(&self.image) {
            return invalid(format!("unknown image {}", self.image));
        }
        if !(1..=16).contains(&self.cpu_cores) {
            return invalid("cpu_cores must be between 1 and 16");
        }
        if !(512..=131_072).contains(&self.memory_mib) {
            return invalid("memory_mib must be between 512 and 131072");
        }
        if !(8..=2048).contains(&self.disk_gib) {
            return invalid("disk_gib must be between 8 and 2048");
        }
        if self.ssh_authorized_keys.is_empty() || self.ssh_authorized_keys.len() > 8 {
            return invalid("between 1 and 8 ssh_authorized_keys are required");
        }
        for key in &self.ssh_authorized_keys {
            validate_ssh_key(key)?;
        }
        validate_username(&self.username)?;
        let metadata = serde_json::to_vec(&self.metadata)
            .map_err(|_| SpecError::Invalid("metadata is not serializable".into()))?;
        if metadata.len() > 64 * 1024 {
            return invalid("metadata must not exceed 64 KiB");
        }
        Ok(())
    }
}

fn validate_username(value: &str) -> Result<(), SpecError> {
    let mut chars = value.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_');
    let rest_ok =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'));
    if first_ok && rest_ok && value.len() <= 32 && value != "root" {
        Ok(())
    } else {
        invalid("username must be a lowercase Linux user name other than root")
    }
}

fn validate_ssh_key(value: &str) -> Result<(), SpecError> {
    const TYPES: [&str; 5] = [
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ];
    let mut parts = value.split_whitespace();
    let (Some(kind), Some(blob)) = (parts.next(), parts.next()) else {
        return invalid("ssh_authorized_keys entries must be OpenSSH public keys");
    };
    let blob_ok = blob.len() >= 16
        && blob.len() <= 4096
        && blob
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    // The comment may contain spaces but never control characters or newlines.
    let clean = value.len() <= 8192 && !value.chars().any(char::is_control);
    if TYPES.contains(&kind) && blob_ok && clean {
        Ok(())
    } else {
        invalid("ssh_authorized_keys entries must be OpenSSH public keys")
    }
}

/// Lower-case DNS label made from a display name; never empty, at most 25 bytes.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
        if out.len() >= 25 {
            break;
        }
    }
    let trimmed = out.trim_end_matches('-').to_owned();
    if trimmed.is_empty() {
        "vm".into()
    } else {
        trimmed
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn images() -> BTreeMap<String, u32> {
        BTreeMap::from([("ubuntu-26.04".to_owned(), 9000)])
    }

    fn spec() -> VmSpec {
        serde_json::from_value(serde_json::json!({
            "region": "heteronet-global",
            "image": "ubuntu-26.04",
            "cpu_cores": 2,
            "memory_mib": 2048,
            "disk_gib": 20,
            "ssh_authorized_keys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAERHnScWeyI8R9LNgXVEJGjb/Cg8sopnWQJlfqkOv02 me@host"]
        }))
        .expect("valid spec")
    }

    #[test]
    fn accepts_a_valid_spec() {
        assert_eq!(spec().validate("heteronet-global", &images()), Ok(()));
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        let bad = serde_json::from_value::<VmSpec>(serde_json::json!({"region": "r", "extra": 1}));
        assert!(bad.is_err());
        let mut s = spec();
        s.cpu_cores = 0;
        assert!(s.validate("heteronet-global", &images()).is_err());
        let mut s = spec();
        s.image = "nope".into();
        assert!(s.validate("heteronet-global", &images()).is_err());
        let mut s = spec();
        s.username = "root".into();
        assert!(s.validate("heteronet-global", &images()).is_err());
        let mut s = spec();
        s.ssh_authorized_keys = vec!["not a key".into()];
        assert!(s.validate("heteronet-global", &images()).is_err());
        let mut s = spec();
        s.ssh_authorized_keys =
            vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAERHnScWeyI8R9\nssh-rsa AAAA".into()];
        assert!(s.validate("heteronet-global", &images()).is_err());
        assert!(spec().validate("other-region", &images()).is_err());
    }

    #[test]
    fn slug_is_a_dns_label() {
        assert_eq!(slug("My Web Server!!"), "my-web-server");
        assert_eq!(slug("!!!"), "vm");
        assert!(slug(&"a".repeat(80)).len() <= 25);
    }
}
