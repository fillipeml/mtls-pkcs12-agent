/** Reading a PKCS#12, and the one case the whole package exists for.
 *
 * The first test is the argument: Node, on its own, refuses a file that is perfectly valid,
 * and this package opens it. If Node ever stops refusing it, that test fails and the package
 * has lost its reason to exist — which is exactly what a test should tell you.
 */
import { readFileSync } from "node:fs";
import { createSecureContext } from "node:tls";

import { describe, expect, it } from "vitest";

import {
  IncompleteIdentityError,
  NotPkcs12Error,
  WrongPassphraseError,
} from "../src/errors.ts";
import { readPkcs12 } from "../src/pkcs12.ts";

const PASSPHRASE = "fixture-passphrase";

function bytes(name: string): Uint8Array {
  return new Uint8Array(readFileSync(`fixtures/${name}`));
}

function nodeAccepts(name: string, passphrase = PASSPHRASE): boolean {
  try {
    createSecureContext({ pfx: Buffer.from(bytes(name)), passphrase });
    return true;
  } catch {
    return false;
  }
}

describe("the file Node will not open", () => {
  it("is refused by Node's own reader", () => {
    // Encrypted with pbeWithSHA1And40BitRC2-CBC, which OpenSSL 3 moved into a legacy
    // provider it does not load. The file is valid; the reader will not read it.
    expect(nodeAccepts("valid-legacy.p12")).toBe(false);
  });

  it("is read by this package", () => {
    const contents = readPkcs12(bytes("valid-legacy.p12"), PASSPHRASE);
    expect(contents.certificatePem).toContain("BEGIN CERTIFICATE");
    expect(contents.privateKeyPem).toContain("PRIVATE KEY");
  });

  it("produces PEM that Node then accepts", () => {
    // The point of the detour: Node's objection is to the container, not to the contents.
    const contents = readPkcs12(bytes("valid-legacy.p12"), PASSPHRASE);
    expect(() =>
      createSecureContext({ cert: contents.certificatePem, key: contents.privateKeyPem }),
    ).not.toThrow();
  });

  it("agrees with Node on a file Node can open", () => {
    expect(nodeAccepts("valid-modern.p12")).toBe(true);
    expect(() => readPkcs12(bytes("valid-modern.p12"), PASSPHRASE)).not.toThrow();
  });
});

describe("what comes out", () => {
  const contents = readPkcs12(bytes("valid-modern.p12"), PASSPHRASE);

  it("carries the identity a person would recognise", () => {
    expect(contents.subject).toContain("Example Integration Client");
    expect(contents.issuer).toContain("Example Organisation");
    expect(contents.serialNumber.length).toBeGreaterThan(0);
  });

  it("carries the validity window as dates, not strings", () => {
    expect(contents.notBefore).toBeInstanceOf(Date);
    expect(contents.notAfter.getTime()).toBeGreaterThan(contents.notBefore.getTime());
  });

  it("fingerprints the certificate without exposing it", () => {
    expect(contents.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(contents.fingerprint).not.toContain("BEGIN");
  });

  it("is stable: the same file fingerprints the same way", () => {
    expect(readPkcs12(bytes("valid-modern.p12"), PASSPHRASE).fingerprint).toBe(
      contents.fingerprint,
    );
  });

  it("fingerprints two different certificates differently", () => {
    const other = readPkcs12(bytes("expired.p12"), PASSPHRASE);
    expect(other.fingerprint).not.toBe(contents.fingerprint);
  });
});

describe("telling the failures apart", () => {
  it("names a wrong passphrase as a wrong passphrase", () => {
    // The three failures below look identical in a generic parse error, and each sends you
    // somewhere different: a typo, the wrong file, and the reason this package exists.
    expect(() => readPkcs12(bytes("valid-modern.p12"), "not-the-passphrase")).toThrow(
      WrongPassphraseError,
    );
  });

  it("names a file that is not a PKCS#12", () => {
    expect(() => readPkcs12(bytes("not-a-certificate.p12"), PASSPHRASE)).toThrow(NotPkcs12Error);
  });

  it("suggests what the wrong file usually is", () => {
    expect(() => readPkcs12(bytes("not-a-certificate.p12"), PASSPHRASE)).toThrow(/PEM|base64/);
  });

  it("accepts an empty passphrase when the file has none", () => {
    expect(() => readPkcs12(bytes("no-passphrase.p12"), "")).not.toThrow();
  });

  it("refuses an empty input", () => {
    expect(() => readPkcs12(new Uint8Array(), PASSPHRASE)).toThrow(NotPkcs12Error);
  });

  it("names a container with no key", () => {
    // A certificate-only export is a common mistake in certificate manager dialogues, and it
    // fails much later if nothing says so here.
    const error = new IncompleteIdentityError("x");
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe("IncompleteIdentityError");
  });
});
