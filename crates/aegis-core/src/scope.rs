use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use url::{Host, Url};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanProfile {
    Passive,
    Safe,
    Standard,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Created,
    Validating,
    Crawling,
    Analyzing,
    Verifying,
    Reporting,
    Completed,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovedTarget {
    pub id: String,
    pub url: String,
    pub allow_private_network: bool,
    pub approval_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanPlan {
    pub target: ApprovedTarget,
    pub profile: ScanProfile,
    pub enabled_checks: Vec<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("target must include an approval note before scanning")]
    MissingApproval,
    #[error("private network targets require explicit advanced approval")]
    PrivateNetworkNotAllowed,
}

pub fn validate_scan_plan(plan: &ScanPlan) -> Result<(), ScopeError> {
    if plan.target.approval_note.trim().is_empty() {
        return Err(ScopeError::MissingApproval);
    }

    if is_private_or_local_target(&plan.target.url) && !plan.target.allow_private_network {
        return Err(ScopeError::PrivateNetworkNotAllowed);
    }

    Ok(())
}

fn is_private_or_local_target(url: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };

    match url.host() {
        Some(Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            domain == "localhost" || domain.ends_with(".localhost")
        }
        Some(Host::Ipv4(ip)) => is_private_or_local_ipv4(ip),
        Some(Host::Ipv6(ip)) => is_private_or_local_ipv6(ip),
        None => false,
    }
}

fn is_private_or_local_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

fn is_private_or_local_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str, allow_private_network: bool, approval_note: &str) -> ApprovedTarget {
        ApprovedTarget {
            id: "target-1".to_string(),
            url: url.to_string(),
            allow_private_network,
            approval_note: approval_note.to_string(),
        }
    }

    #[test]
    fn rejects_missing_approval_note() {
        let plan = ScanPlan {
            target: target("https://example.com", false, " "),
            profile: ScanProfile::Safe,
            enabled_checks: vec!["passive".to_string()],
        };

        assert_eq!(validate_scan_plan(&plan), Err(ScopeError::MissingApproval));
    }

    #[test]
    fn rejects_private_network_without_advanced_approval() {
        let plan = ScanPlan {
            target: target(
                "http://192.168.0.10",
                false,
                "internal staging target approved",
            ),
            profile: ScanProfile::Safe,
            enabled_checks: vec!["passive".to_string()],
        };

        assert_eq!(
            validate_scan_plan(&plan),
            Err(ScopeError::PrivateNetworkNotAllowed)
        );
    }

    #[test]
    fn rejects_loopback_and_localhost_without_advanced_approval() {
        for url in [
            "http://127.0.0.1:8080",
            "http://localhost:3000",
            "http://service.localhost",
            "http://[::1]:8080",
        ] {
            let plan = ScanPlan {
                target: target(url, false, "owned local target"),
                profile: ScanProfile::Safe,
                enabled_checks: vec!["passive".to_string()],
            };

            assert_eq!(
                validate_scan_plan(&plan),
                Err(ScopeError::PrivateNetworkNotAllowed),
                "{url} should require advanced approval"
            );
        }
    }

    #[test]
    fn rejects_private_ip_ranges_without_advanced_approval() {
        for url in [
            "http://10.1.2.3",
            "http://172.16.0.1",
            "http://172.31.255.254",
            "http://192.168.1.20",
            "http://169.254.10.20",
            "http://[fd00::1]",
            "http://[fe80::1]",
        ] {
            let plan = ScanPlan {
                target: target(url, false, "owned private target"),
                profile: ScanProfile::Safe,
                enabled_checks: vec!["passive".to_string()],
            };

            assert_eq!(
                validate_scan_plan(&plan),
                Err(ScopeError::PrivateNetworkNotAllowed),
                "{url} should require advanced approval"
            );
        }
    }

    #[test]
    fn accepts_public_hostnames_that_contain_private_like_text() {
        for url in [
            "https://not10.example.com",
            "https://public-192.168.example.com",
            "https://172.16.example.com",
        ] {
            let plan = ScanPlan {
                target: target(url, false, "owned public target"),
                profile: ScanProfile::Safe,
                enabled_checks: vec!["passive".to_string()],
            };

            assert_eq!(validate_scan_plan(&plan), Ok(()), "{url} should pass");
        }
    }

    #[test]
    fn accepts_public_approved_target() {
        let plan = ScanPlan {
            target: target("https://staging.example.com", false, "owned staging target"),
            profile: ScanProfile::Safe,
            enabled_checks: vec!["passive".to_string(), "surface".to_string()],
        };

        assert_eq!(validate_scan_plan(&plan), Ok(()));
    }
}
