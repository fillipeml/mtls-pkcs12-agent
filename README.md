# mtls-pkcs12-agent

Mutual-TLS HTTPS agents in Node from a PKCS#12 certificate — including the files Node itself
refuses to open, and without ever writing the private key to disk.

![CI](https://github.com/fillipeml/mtls-pkcs12-agent/actions/workflows/ci.yml/badge.svg) ![Licence: MIT](https://img.shields.io/badge/licence-MIT-informational)

**Status:** extracted from a production integration with a government API · **Runs offline:**
yes, on generated certificates, with no network and no real credential anywhere

```
$ npm run mtls -- compare fixtures/valid-legacy.p12 --passphrase fixture-passphrase
node's own PKCS#12 reader : REFUSES it — ERR_CRYPTO_UNSUPPORTED_OPERATION Unsupported PKCS12 PFX data
this package              : accepts it

This is the case the package is for. Node ships OpenSSL 3, which moved the older
PKCS#12 encryption algorithms into a legacy provider it does not load, so a file
that is perfectly valid becomes unreadable. Nothing is wrong with the certificate.

$ npm run mtls -- inspect fixtures/valid-modern.p12 --passphrase fixture-passphrase
subject      CN=Example Integration Client, O=Example Organisation, C=ZZ
issuer       CN=Example Integration Client, O=Example Organisation, C=ZZ
serial       0176616c69642d6d6f
fingerprint  8a9e5fab092810326c315f73e1a752df2c229bd97014d7d1a7a457b2f02ce1de
valid        2026-01-01 to 2065-12-22
chain        0 intermediate certificate(s) in the file
status       usable, 14327 day(s) left

$ npm run mtls -- check fixtures/expired.p12 --passphrase fixture-passphrase
FAIL  CN=Example Expired Client: the certificate expired on 2026-01-11 and no handshake
      using it will succeed
```

## Why this exists

Node can build a TLS context straight from a `.pfx`, so a package that parses one in
JavaScript needs a reason. Here it is, reproducible in two commands:

```bash
openssl pkcs12 -export -legacy -out legacy.pfx -inkey key.pem -in cert.pem
node -e 'require("tls").createSecureContext({pfx:require("fs").readFileSync("legacy.pfx"),passphrase:"..."})'
# ERR_CRYPTO_UNSUPPORTED_OPERATION: Unsupported PKCS12 PFX data
```

Node 17 and later ship OpenSSL 3, which moved the old PKCS#12 encryption algorithms —
`pbeWithSHA1And40BitRC2-CBC` above all — into a legacy provider that is not loaded by default.
A file produced by older tooling is therefore unreadable by Node while remaining perfectly
valid, and the error names neither the algorithm nor the fix.

Certificate authorities that issue client certificates to organisations were still exporting
in exactly that shape long after OpenSSL 3 shipped, so anyone integrating with a government,
banking or healthcare API meets this. The usual workaround — shell out to `openssl` to convert
the file, and keep the converted PEM somewhere — puts an unencrypted private key on a disk.

`node-forge` implements the ciphers in JavaScript and does not care what OpenSSL will load.
This package wraps that: parse in memory, hand the PEM straight to `tls.createSecureContext`,
write nothing.

Verified on Node 24.15 with OpenSSL 3.5.5 on 30 September 2026. `npm test` reproduces both
halves — Node's refusal and this package's success — against generated fixtures, so if Node
ever stops refusing, a test says so.

## Use

```bash
npm install
npm run fixtures                # generate the test certificates
npm test
npm run mtls -- env             # the environment variables it reads
```

```typescript
import { fromEnv, createAgent, AgentCache } from "mtls-pkcs12-agent";

const identity = fromEnv();                       // base64 env var, or a path
console.log(identity.summary());                  // facts only: no key, no certificate

const warning = identity.expiryWarning();
if (warning) logger.warn(warning);                // weeks before, not during a handshake

const agent = createAgent(identity, {
  caPem: readFileSync("issuing-chain.pem", "utf8"),
});

await fetch("https://api.example.gov/v1/status", { dispatcher: agent });
```

For a service holding one certificate per customer, `AgentCache` keeps an agent per
certificate so the TLS session cache is reused:

```typescript
const cache = new AgentCache({ caPem });
const agent = cache.get(identityForCustomer);     // keyed on the certificate's fingerprint
```

## Design decisions

**Server verification stays on, and the way to turn it off is spelled out in full.**
`rejectUnauthorized: false` is the answer every forum gives to "unable to verify the first
certificate", and on a mutual-TLS connection it is worse than usual: the whole point of the
client certificate is to prove who you are, and with verification off you may be proving it to
whoever answered the DNS query. The real cause is nearly always a server that does not send
its intermediate, and the real fix is `caPem`. So the escape hatch here is called
`dangerouslyDisableServerVerification`, has to be passed explicitly, and fires the `onWarning`
hook every time an agent is built with it.

This is the one behaviour that changed on the way out of the original project, which carried
`rejectUnauthorized: false` unconditionally. Extracting a component is a good moment to stop
inheriting a default nobody chose.

**The expiry check is the feature, not a nicety.** A client certificate issued to an
organisation lasts about a year and expires while nothing is being deployed, so the first
symptom is a handshake failing one morning with an error from the far side that says nothing
about dates. `createAgent` refuses an expired identity and names the date; `expiryWarning`
returns a string weeks earlier; `mtls check` exits 0, 1 or 2 so a cron job can page somebody.

**The failures are told apart.** A container that will not open has three plausible causes —
the wrong passphrase, a file that is not a PKCS#12, and an encryption algorithm the reader
cannot handle — and they are indistinguishable in a generic parse error. They get three
classes and three messages, because each sends you somewhere completely different.

**The key never touches the disk.** Not in this package, and not in the suggested workflow. A
key written to a temporary file to satisfy a path-only API survives a crash, lands in a
container layer, and is readable by anything running as the same user. Loading from a base64
environment variable is a first-class path for exactly this reason.

**Nothing prints the key.** `toString`, `toJSON` and every CLI command show the subject, the
issuer, the serial, the validity and a SHA-256 fingerprint — enough to say *which* certificate
this is, and nothing usable. The fingerprint is also the cache key, because in a service
holding a certificate per customer a cache keyed on a path or a tenant id is one refactor away
from handing one customer's identity to another customer's request, silently.

**The leaf is chosen, not assumed.** Bag order in a PKCS#12 is not guaranteed, and taking the
first certificate gets it wrong on files where the CA is stored first — which fails the
handshake with an error about the wrong certificate being presented.

## Commands

| Command | For |
| --- | --- |
| `inspect <file>` | What is in it, and how long it has left |
| `check <file> [--warn-days N]` | Exit 0 usable, 1 expiring, 2 unusable. For a cron job |
| `compare <file>` | Whether Node accepts this file on its own |
| `probe <url> --cert <file> [--ca <file>]` | One request, with the likely cause named if the handshake fails |
| `env` | The environment variables it reads |

## Known failure modes

Four, and what this package does about each.

**A certificate that expires while nothing is being deployed.** A client certificate issued to
an organisation typically lasts a year, so the first symptom is a handshake failing one morning
with an error from the far side that says nothing about dates. `createAgent` refuses an expired
identity and names the date, `expiryWarning` returns a string weeks earlier, and `mtls check`
exits 0, 1 or 2 so a scheduled job can page somebody before it happens.

**A container that will not open, for three different reasons.** The wrong passphrase, a file
that is not a PKCS#12 at all, and an encryption algorithm the reader cannot handle are
indistinguishable in a generic parse error, and each sends you somewhere completely different:
a typo, the wrong file, and the reason this package exists. They get three classes and three
messages.

**A clock that is wrong rather than a certificate that is.** A machine whose time is skewed
produces "not yet valid" exactly as a genuinely future-dated certificate would, so the error
message says to check the clock before assuming the file is at fault.

**A server that cannot be verified.** The usual cause is a server that does not send its
intermediate, and the usual fix found online is to disable verification — which, on a mutual-TLS
connection, means presenting your client certificate to whatever host answered. The supported
fix is `caPem`; the escape hatch is named `dangerouslyDisableServerVerification`, must be passed
explicitly, and warns every time. The `probe` command recognises the two Node error codes that
mean this and says so rather than leaving you to search for it.

One thing this package does **not** solve: the certificate still has to be stored somewhere
between runs. Loading it from a base64 environment variable keeps it off the filesystem, which
is the common case this was built for, but a service holding one certificate per customer needs
an answer about encryption at rest that is outside the scope of a client library.

## How AI was used

No model is involved at runtime.

An AI coding assistant was used to build it, and the part that matters is that **the premise
was verified by running it rather than asserted**. The claim this package rests on — that Node
refuses a PKCS#12 file which is perfectly valid — was tested by generating both a legacy and a
modern container and feeding each to Node's own reader. That test is in the suite, so if Node
ever stops refusing the legacy one, the package has lost its reason to exist and CI says so.

That check also corrected a first attempt: a fixture generated with 3DES, which looked like the
right "legacy" choice, is still accepted by Node and did not reproduce the failure at all. The
algorithm that matters is RC2-40-CBC, which no JavaScript library writes any more — so that one
fixture has to be built by the `openssl` binary, and the fixture generator says why.

**Rejected:** the insecure TLS default inherited from the project this was extracted from. The
original set `rejectUnauthorized: false` unconditionally, in the client and in all six of its
probe scripts. Carrying that over would have been the path of least resistance and is the single
behaviour that changed on the way out — extracting a component is a good moment to stop
inheriting a default nobody chose.

Two smaller ones worth recording because both were caught by tooling rather than by reading. A
constant named `SHROUDED_KEY_BAG` tripped the secret scanner's generic-key rule; renaming it
beat allowlisting it, because an allowlist entry is a permanent hole and a rename is not. And
the CI guard that checks no insecure TLS assignment exists in the source was matching the module
docstring that *explains why the package does not use one* — so it now matches an assignment
rather than a mention.

**Validated:** CI asserts the behaviour rather than only running the suite — that Node refuses
the legacy fixture and this package opens it, that an expired certificate exits 2, that no
command prints a private key, and that no insecure TLS assignment exists in the source.
Commits were made with an AI assistant; attribution trailers are omitted and the usage is
documented here.

## Data and privacy

This package handles private keys, so nearly all of it is privacy-relevant.

The key exists only in memory and is never written to disk by this package. That is not a
convenience: the common workaround for the OpenSSL problem above is to convert the file with
the `openssl` binary and keep the resulting PEM, which puts an unencrypted private key on a
disk where it survives a crash, lands in a container layer, and is readable by anything running
as the same user.

Nothing prints the key. `toString`, `toJSON` and every command show the subject, the issuer, the
serial, the validity window and a SHA-256 fingerprint — enough to say *which* certificate this
is, and nothing usable. CI greps the command output to keep it that way.

Every certificate in this repository is generated by `npm run fixtures`: self-signed, synthetic,
issued to a fictional organisation under a reserved country code, with a throwaway key created
seconds beforehand. Their private keys are published on purpose, which is why they are
allowlisted for the secret scanner by path — with the two compensating controls stated in
`.gitleaks.toml`.

## Tests

```bash
npm test          # 61 tests
npm run typecheck
npm run lint
```

Every certificate in the suite is generated by `npm run fixtures`: self-signed, synthetic,
organisation "Example Organisation" in country `ZZ`. A fixture that is a real certificate is a
real certificate in a public repository. One of them is built with the `openssl` binary
specifically so it uses the RC2 encryption no JavaScript library writes any more — which is
the algorithm that matters, and the reason that one file has to come from openssl.

## Built with

Node 24 with native type stripping, TypeScript, node-forge, vitest. No build step. Developed
with an AI coding assistant; the OpenSSL 3 behaviour at the centre of the package was verified
by running it rather than taken on trust, and the reproduction is in the README above.

## Licence

MIT — see [LICENSE](LICENSE).
