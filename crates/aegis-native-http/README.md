# aegis-native-http

Sandboxed async HTTP adapter for `aegis-native-engine`.

- validates every request against an exact approved target;
- resolves and classifies all DNS answers before connecting;
- pins the HTTP client to a validated socket address;
- disables environment proxies and automatic redirects;
- revalidates same-scope redirects manually;
- enforces timeout, redirect, and streamed response byte limits;
- uses rustls certificate validation without an insecure fallback;
- keeps bounded response bytes only in worker memory and emits redacted records.

The loopback policy used in unit tests is private to the test module. Production
callers use `PublicAddressPolicy`.

```bash
cargo test --manifest-path crates/aegis-native-http/Cargo.toml
```
