/** Mutual-TLS HTTPS agents in Node from a PKCS#12 certificate.
 *
 *     import { fromFile, createAgent } from "mtls-pkcs12-agent";
 *
 *     const identity = fromFile("client.p12", process.env.PASSPHRASE ?? "");
 *     console.log(identity.summary());          // no key, no certificate, just the facts
 *     const agent = createAgent(identity, { caPem: readFileSync("chain.pem", "utf8") });
 *
 * Two things this package does that `new https.Agent({ pfx })` does not: it opens the files
 * OpenSSL 3 declines to load, and it tells you when the certificate is about to expire
 * instead of letting you find out during a handshake one morning.
 */
export { AgentCache, createAgent, type AgentOptions } from "./agent.ts";
export {
  CertificateExpiredError,
  IncompleteIdentityError,
  NotPkcs12Error,
  Pkcs12Error,
  WrongPassphraseError,
} from "./errors.ts";
export { DEFAULT_WARN_DAYS, Identity, type IdentitySummary } from "./identity.ts";
export { readPkcs12, type Pkcs12Contents } from "./pkcs12.ts";
export {
  DEFAULT_ENV,
  fromBase64,
  fromBytes,
  fromEnv,
  fromFile,
  isConfigured,
  type EnvNames,
} from "./source.ts";
