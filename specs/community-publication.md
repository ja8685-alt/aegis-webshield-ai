# Community publication contract

- All implemented application features are accessible without a plan, license key,
  online account, or monthly usage allowance.
- Report formats and AI requests remain subject to input validation and redaction.
  AI additionally requires the user's provider key and incurs provider charges.
- Bounded scan concurrency and network/file/crawler safety policies remain enforced.
- Every supported rule channel works without activation; signatures and invalid paths
  are still checked. Unknown channels are rejected.
- Historical SQLite migrations remain compatible. Live databases are never copied
  into a public package or removed by publication tooling.
- Public packaging uses a reviewed, explicit list of relative files, rejects symlinks,
  data/credential extensions and secret-scan findings, and never overwrites output.
- The source archive excludes `.git`, internal planning, private remotes, author history,
  environment files, application data, credentials, build outputs, and release evidence.
- A SHA-256 manifest identifies every exported file and the ZIP without private paths.
- The public source can be built without the original checkout or private services.
- README covers the same product behavior and limitations in Korean and English.

## Final destination decision

- Publish a fresh source snapshot to a new repository, as the user's final decision.
- Do not rewrite the existing remote or change its visibility.
- Keep private backups and sanitized-history candidates outside the new repository.
- Confirm the new destination and public-safe Git author identity before its first push.
- Publish only the reviewed inventory, with no inherited Git history or remote configuration.
- Verify hosted CI and configure a working private security-reporting route.
