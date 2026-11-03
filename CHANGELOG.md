# Changelog

## Community source preview — 2026-11-03

- Removed paid tiers, activation commands/UI, monthly quotas, and paid report/AI gates.
- Accepted all supported rule channel labels without a subscription; schema, hash,
  signature, and archive safety checks remain.
- Kept local scan concurrency and network/resource safety controls.
- Preserved existing project/target/scan data and historical SQL migrations.
- Added Korean/English README, Apache-2.0 licensing, contribution/security guidance,
  public-source packaging, dependency inventory, and CI.
- Removed `--pro-active` from CLI feed/bundle checks. The legacy JSON
  `entitlement_allowed` field now means that the channel is supported.
- Diagnostics include `edition: community` instead of license/account metadata.

Windows installers and real device/platform behavior require separate release validation.
