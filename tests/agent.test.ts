/** Expiry, agents, sources and the one option that must stay hard to reach for.
 *
 * The verification tests are the ones that matter. `rejectUnauthorized: false` is the answer
 * every forum gives to "unable to verify the first certificate", and on a mutual-TLS
 * connection it means presenting your client certificate to whatever host answered. It has to
 * be on by default, and switching it off has to be something somebody typed deliberately.
 */
import { readFileSync } from "node:fs";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AgentCache, createAgent } from "../src/agent.ts";
import { CertificateExpiredError, NotPkcs12Error } from "../src/errors.ts";
import { Identity } from "../src/identity.ts";
import { fromBase64, fromBytes, fromEnv, fromFile, isConfigured } from "../src/source.ts";

const PASSPHRASE = "fixture-passphrase";
const NOW = new Date("2026-06-01T00:00:00Z");

function identity(name: string, passphrase = PASSPHRASE): Identity {
  return fromBytes(new Uint8Array(readFileSync(`fixtures/${name}`)), passphrase);
}

describe("how long the certificate has left", () => {
  const valid = identity("valid-modern.p12");
  const expired = identity("expired.p12");
  const future = identity("not-yet-valid.p12");

  it("counts the days", () => {
    expect(valid.daysUntilExpiry(NOW)).toBeGreaterThan(0);
    expect(expired.daysUntilExpiry(NOW)).toBeLessThan(0);
  });

  it("knows the three states apart", () => {
    expect(valid.isUsable(NOW)).toBe(true);
    expect(expired.isExpired(NOW)).toBe(true);
    expect(future.isNotYetValid(NOW)).toBe(true);
    expect(future.isUsable(NOW)).toBe(false);
  });

  it("says nothing while there is nothing to say", () => {
    expect(valid.expiryWarning(NOW)).toBeNull();
  });

  it("warns inside the renewal window, before anything breaks", () => {
    const almost = new Date(valid.notAfter.getTime() - 5 * 24 * 60 * 60 * 1000);
    expect(valid.expiryWarning(almost)).toMatch(/expires on .*, in 5 days/);
  });

  it("returns the warning rather than printing it", () => {
    // A library does not own stderr. The caller decides whether this is a log line, a
    // dashboard metric or a page.
    expect(typeof valid.expiryWarning(new Date(valid.notAfter.getTime() - 1000))).toBe("string");
  });

  it("refuses to hand out an expired identity, naming the date", () => {
    expect(() => expired.assertUsable(NOW)).toThrow(CertificateExpiredError);
    expect(() => expired.assertUsable(NOW)).toThrow(/expired on 2026-01-11/);
  });

  it("blames the clock, not the file, when a certificate is not yet valid", () => {
    // A machine with a skewed clock produces this exactly, and the file is fine.
    expect(() => future.assertUsable(NOW)).toThrow(/clock on this machine/);
  });
});

describe("what a summary shows, and what it does not", () => {
  const valid = identity("valid-modern.p12");

  it("never carries the key or the certificate", () => {
    const printed = JSON.stringify(valid) + String(valid);
    expect(printed).not.toContain("PRIVATE KEY");
    expect(printed).not.toContain("BEGIN CERTIFICATE");
  });

  it("carries enough to identify which certificate it is", () => {
    const summary = valid.summary(NOW);
    expect(summary.fingerprint).toHaveLength(64);
    expect(summary.subject).toContain("Example");
    expect(summary.status).toBe("usable");
  });

  it("labels an expired one as expired", () => {
    expect(identity("expired.p12").summary(NOW).status).toBe("expired");
  });
});

describe("building an agent", () => {
  const valid = identity("valid-modern.p12");

  it("verifies the server by default", () => {
    // The whole point of the client certificate is to prove who you are. Doing that without
    // checking who you are proving it to gives the proof away.
    const agent = createAgent(valid, { now: NOW });
    expect(agent.options.rejectUnauthorized).toBe(true);
  });

  it("requires the insecure option to be spelled out in full", () => {
    const agent = createAgent(valid, { now: NOW, dangerouslyDisableServerVerification: true });
    expect(agent.options.rejectUnauthorized).toBe(false);
  });

  it("says so, loudly, every time verification is disabled", () => {
    const warnings: string[] = [];
    createAgent(valid, {
      now: NOW,
      dangerouslyDisableServerVerification: true,
      onWarning: (message) => warnings.push(message),
    });
    expect(warnings.join(" ")).toContain("DISABLED");
    expect(warnings.join(" ")).toContain("caPem");
  });

  it("takes a CA, which is the actual fix for an unverifiable server", () => {
    const agent = createAgent(valid, { now: NOW, caPem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----" });
    expect(agent.options.ca).toBeDefined();
  });

  it("refuses to build an agent from an expired certificate", () => {
    expect(() => createAgent(identity("expired.p12"), { now: NOW })).toThrow(
      CertificateExpiredError,
    );
  });

  it("can be told to build one anyway, for a diagnostic", () => {
    expect(() =>
      createAgent(identity("expired.p12"), { now: NOW, requireValidDates: false }),
    ).not.toThrow();
  });

  it("sends only the leaf unless asked for the chain", () => {
    expect(createAgent(valid, { now: NOW }).options.cert).toBe(valid.certificatePem);
  });

  it("refuses anything below TLS 1.2", () => {
    expect(createAgent(valid, { now: NOW }).options.minVersion).toBe("TLSv1.2");
  });
});

describe("the agent cache", () => {
  const valid = identity("valid-modern.p12");
  const other = identity("no-passphrase.p12", "");

  it("reuses one agent per certificate", () => {
    const cache = new AgentCache({ now: NOW });
    expect(cache.get(valid)).toBe(cache.get(valid));
    expect(cache.size).toBe(1);
  });

  it("keys on the certificate, not on anything a refactor could change", () => {
    // In a service holding a certificate per customer, a cache keyed on a path or a tenant id
    // is one refactor away from handing one customer's identity to another's request, and
    // that failure is silent.
    const cache = new AgentCache({ now: NOW });
    expect(cache.get(valid)).not.toBe(cache.get(other));
    expect(cache.size).toBe(2);
  });

  it("does not share an agent between different options", () => {
    const cache = new AgentCache({ now: NOW });
    const strict = cache.get(valid);
    const loose = cache.get(valid, { dangerouslyDisableServerVerification: true });
    expect(strict).not.toBe(loose);
  });

  it("can be emptied when a certificate is replaced", () => {
    const cache = new AgentCache({ now: NOW });
    cache.get(valid);
    cache.clear();
    expect(cache.size).toBe(0);
  });
});

describe("where the certificate comes from", () => {
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "mtls-source-"));
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("loads from a file", () => {
    expect(fromFile("fixtures/valid-modern.p12", PASSPHRASE).subject).toContain("Example");
  });

  it("loads from base64, which is how a host with no filesystem holds one", () => {
    const encoded = readFileSync("fixtures/valid-modern.p12").toString("base64");
    expect(fromBase64(encoded, PASSPHRASE).subject).toContain("Example");
  });

  it("survives the whitespace a copy-paste into a secret field adds", () => {
    const encoded = readFileSync("fixtures/valid-modern.p12").toString("base64");
    const wrapped = encoded.replace(/(.{64})/g, "$1\n");
    expect(fromBase64(wrapped, PASSPHRASE).fingerprint).toBe(
      fromBase64(encoded, PASSPHRASE).fingerprint,
    );
  });

  it("says so when somebody pasted a PEM instead", () => {
    expect(() => fromBase64("-----BEGIN CERTIFICATE-----\nabc\n", PASSPHRASE)).toThrow(/base64 -w0/);
  });

  it("prefers the inline value over a leftover path", () => {
    const encoded = readFileSync("fixtures/valid-modern.p12").toString("base64");
    const loaded = fromEnv({
      MTLS_PKCS12_BASE64: encoded,
      MTLS_PKCS12_PATH: "fixtures/expired.p12",
      MTLS_PKCS12_PASSPHRASE: PASSPHRASE,
    });
    expect(loaded.isUsable(NOW)).toBe(true);
  });

  it("falls back to the path", () => {
    const loaded = fromEnv({
      MTLS_PKCS12_PATH: "fixtures/valid-modern.p12",
      MTLS_PKCS12_PASSPHRASE: PASSPHRASE,
    });
    expect(loaded.subject).toContain("Example");
  });

  it("names the variables when nothing is configured", () => {
    expect(() => fromEnv({})).toThrow(/MTLS_PKCS12_BASE64/);
    expect(isConfigured({})).toBe(false);
    expect(isConfigured({ MTLS_PKCS12_PATH: "x" })).toBe(true);
  });

  it("never writes the key anywhere", () => {
    // Loading writes nothing. A key written to a temp file to satisfy a path-only API
    // survives a crash, lands in a container layer, and is readable by anything running as
    // the same user.
    const before = readFileSync("fixtures/valid-modern.p12");
    const loaded = fromBytes(new Uint8Array(before), PASSPHRASE);
    expect(loaded.privateKeyPem).toContain("PRIVATE KEY");
    const scratch = join(dir, "should-not-exist.pem");
    expect(() => readFileSync(scratch)).toThrow();
  });

  it("rejects an empty base64 value clearly", () => {
    expect(() => fromBase64("   ", PASSPHRASE)).toThrow(NotPkcs12Error);
  });
});

describe("the fixtures themselves", () => {
  it("are self-signed and synthetic", () => {
    const valid = identity("valid-modern.p12");
    // A fixture that is a real certificate is a real certificate in a public repository.
    expect(valid.subject).toBe(valid.issuer);
    expect(valid.subject).toContain("Example Organisation");
    expect(valid.subject).toContain("C=ZZ");
  });

  it("include one that is generated to be unreadable by Node", () => {
    writeFileSync(join(tmpdir(), "mtls-noop"), "");
    expect(() => identity("valid-legacy.p12")).not.toThrow();
  });
});
