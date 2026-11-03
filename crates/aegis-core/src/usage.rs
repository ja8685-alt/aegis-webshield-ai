use serde::{Deserialize, Serialize};

/// Resource protection for the local runner, independent of usage or license history.
pub const MAX_CONCURRENT_SCANS: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageSnapshot {
    pub monthly_scans: u32,
    pub projects: u32,
    pub targets: u32,
    pub reports: u32,
    pub ai_fix_guides: u32,
    pub active_scans: u32,
}

impl UsageSnapshot {
    pub fn scan_capacity_available(&self) -> bool {
        self.active_scans < MAX_CONCURRENT_SCANS
    }
}

/// Legacy channel names are accepted as labels, without paid entitlements.
pub fn rule_pack_channel_supported(channel: &str) -> bool {
    matches!(
        channel,
        "built-in" | "community" | "local" | "pro" | "team" | "enterprise"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulated_usage_never_exhausts_scan_access() {
        let usage = UsageSnapshot {
            monthly_scans: u32::MAX,
            projects: u32::MAX,
            targets: u32::MAX,
            reports: u32::MAX,
            ai_fix_guides: u32::MAX,
            active_scans: 0,
        };
        assert!(usage.scan_capacity_available());
        assert!(!UsageSnapshot {
            active_scans: MAX_CONCURRENT_SCANS,
            ..usage
        }
        .scan_capacity_available());
        assert!(UsageSnapshot {
            active_scans: MAX_CONCURRENT_SCANS - 1,
            ..usage
        }
        .scan_capacity_available());
    }

    #[test]
    fn all_known_rule_channels_are_available_without_activation() {
        for channel in [
            "built-in",
            "community",
            "local",
            "pro",
            "team",
            "enterprise",
        ] {
            assert!(rule_pack_channel_supported(channel));
        }
        for channel in ["", "unknown", "../local", "PRO"] {
            assert!(!rule_pack_channel_supported(channel));
        }
    }
}
