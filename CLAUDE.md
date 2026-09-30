# CLAUDE.md

Working rules for AI-assisted changes in this repository. They mirror the README; the README
wins on conflict.

## Non-negotiable rules

1. **The private key never leaves memory.** Not to a temporary file, not to a log, not into
   `toString`, `toJSON` or any CLI output. Certificates are identified by their SHA-256
   fingerprint. CI greps for `PRIVATE KEY` and `BEGIN CERTIFICATE` in command output.
2. **Server verification stays on by default.** `rejectUnauthorized` is derived from
   `dangerouslyDisableServerVerification` and from nothing else, the option keeps that name,
   and it warns through `onWarning` every time it is used. The documented fix for an
   unverifiable server is `caPem`. CI greps for a literal `rejectUnauthorized: false` in `src/`.
3. **The AgentCache is keyed on the fingerprint.** Not on a path, a tenant id or a label. In a
   service holding one certificate per customer, any other key is one refactor away from
   serving one customer's identity on another's request, silently.
4. **Failures stay told apart.** A wrong passphrase, a file that is not a PKCS#12, an
   incomplete container and an expired certificate are four classes with four messages,
   because each sends a reader somewhere different.
5. **Fixtures are generated, synthetic and self-signed.** `npm run fixtures` builds them all;
   never commit a real certificate, and never generate one with a real organisation's name.
   `valid-legacy.p12` must keep being built by the `openssl` binary with `-legacy`, because
   RC2 is the algorithm that matters and no JavaScript library writes it.
6. **The OpenSSL claim is tested, not asserted.** `tests/pkcs12.test.ts` checks that Node
   refuses the legacy fixture and that this package opens it. If Node ever stops refusing it,
   that test fails and the package has lost its reason to exist — leave the test as the thing
   that says so.

## Conventions

- Node 24 with native type stripping, TypeScript 5, vitest 5, node-forge. No build step.
- `erasableSyntaxOnly` is on: no parameter properties, no enums.
- Modules import siblings with explicit `.ts` extensions.
- The public surface is `src/index.ts`; anything exported there has a test.
- A library returns warnings; it does not print them. The caller owns stderr.
- Never commit `.env*` (except `.env.example`), `/certs` or `/private`.
- Commits: English, Conventional Commits, one logical change each, no AI attribution trailers.
