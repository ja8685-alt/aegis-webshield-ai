# aegis-native-engine

Deployment-neutral Rust core for request planning, rule evaluation, evidence
normalization, and canonical finding decisions.

The crate may depend on deterministic parsing, URL, serialization, crypto, and
async abstraction libraries. It must not depend directly on Axum, SQLx,
MongoDB, NATS, subprocess execution, AI provider SDKs, or a concrete HTTP
client. Those integrations are injected through ports and implemented by the
scanner worker or control plane.

The scanner worker is the only role allowed to connect to an approved target
or briefly hold decrypted credentials. The FastAPI AI service receives only
bounded, redacted evidence.

Run the contract tests with:

```bash
cargo test --manifest-path crates/aegis-native-engine/Cargo.toml
```
