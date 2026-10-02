# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-09-30

First public release: mutual-TLS HTTPS agents from a PKCS#12 certificate, extracted from a production integration with a government API.

### Added

- Reading a PKCS#12 container in JavaScript, which opens the files Node itself refuses. Node 17 and later ship OpenSSL 3, which moved the older PKCS#12 encryption algorithms into a legacy provider it does not load, so a valid file produced by older tooling is unreadable and the error names neither the algorithm nor the fix.
- The private key handled only in memory, never written to disk, and kept out of every `toString`, `toJSON`, log line and command output. Certificates are identified by a SHA-256 fingerprint instead.
- Four distinct failures with four messages: a wrong passphrase, bytes that are not a PKCS#12, a container missing its certificate or key, and a certificate outside its validity window.
- Certificate expiry as a first-class concern: `daysUntilExpiry`, an `expiryWarning` the caller decides what to do with, an `assertUsable` that names the date, and a `check` command that exits 0, 1 or 2 for a cron job.
- `createAgent` with server verification on by default. The escape hatch is named `dangerouslyDisableServerVerification`, must be passed explicitly, and warns every time; the documented fix for an unverifiable server is `caPem`. The original this was extracted from disabled verification unconditionally.
- `AgentCache`, keyed on the certificate's fingerprint so a service holding one certificate per customer cannot serve one customer's identity on another's request.
- Loading from a file, from a base64 environment variable or from raw bytes, with the two mistakes that actually happen named: whitespace from a copy-paste into a secret field, and a PEM pasted where base64 belongs.
- The leaf certificate chosen rather than assumed, since bag order in a PKCS#12 is not guaranteed and taking the first one fails the handshake on files where the CA is stored first.
- A command line: `inspect`, `check`, `compare`, `probe` and `env`.
- Generated, self-signed, synthetic fixtures, including one built with the `openssl` binary specifically so it uses RC2 encryption, which is the algorithm that matters and which no JavaScript library writes.
- 65 offline tests, and CI that asserts the behaviour rather than only running the suite: that Node refuses the legacy fixture and this package opens it, that an expired certificate exits 2, that no command prints a key, and that no literal insecure TLS flag exists in the source.

[0.1.0]: https://github.com/fillipeml/mtls-pkcs12-agent/releases/tag/v0.1.0
