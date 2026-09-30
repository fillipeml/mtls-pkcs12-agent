/** The command line, which is what somebody actually reaches for when a handshake fails.
 *
 * The exit codes are the contract: `check` is meant to be a cron job, so 0, 1 and 2 have to
 * mean usable, expiring and unusable, and stay meaning that.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { main } from "../src/cli.ts";

const PASSPHRASE = ["--passphrase", "fixture-passphrase"];

let written: string[] = [];

beforeEach(() => {
  written = [];
  vi.spyOn(process.stdout, "write").mockImplementation((chunk: unknown) => {
    written.push(String(chunk));
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
    written.push(String(chunk));
    return true;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

const output = (): string => written.join("");

describe("compare", () => {
  it("shows Node refusing the file and this package opening it", async () => {
    const code = await main(["compare", "fixtures/valid-legacy.p12", ...PASSPHRASE]);
    expect(code).toBe(0);
    expect(output()).toContain("REFUSES it");
    expect(output()).toContain("this package              : accepts it");
  });

  it("explains that nothing is wrong with the certificate", async () => {
    // The message that saves the afternoon: the file is fine, the reader is not.
    await main(["compare", "fixtures/valid-legacy.p12", ...PASSPHRASE]);
    expect(output()).toContain("Nothing is wrong with the certificate");
  });

  it("shows both accepting a modern file", async () => {
    await main(["compare", "fixtures/valid-modern.p12", ...PASSPHRASE]);
    expect(output()).toContain("node's own PKCS#12 reader : accepts it");
  });
});

describe("inspect", () => {
  it("prints the facts and never the key", async () => {
    const code = await main(["inspect", "fixtures/valid-modern.p12", ...PASSPHRASE]);
    expect(code).toBe(0);
    expect(output()).toContain("Example Integration Client");
    expect(output()).toMatch(/fingerprint {2}[0-9a-f]{64}/);
    expect(output()).not.toContain("PRIVATE KEY");
    expect(output()).not.toContain("BEGIN CERTIFICATE");
  });

  it("exits non-zero on a certificate that cannot be used", async () => {
    expect(await main(["inspect", "fixtures/expired.p12", ...PASSPHRASE])).toBe(1);
  });
});

describe("check, which is meant for a cron job", () => {
  it("exits 0 while there is plenty of time", async () => {
    expect(await main(["check", "fixtures/valid-modern.p12", ...PASSPHRASE])).toBe(0);
    expect(output()).toContain("OK");
  });

  it("exits 1 inside the warning window", async () => {
    // The whole point: a warning weeks before, rather than a handshake failure one morning.
    const code = await main([
      "check",
      "fixtures/valid-modern.p12",
      ...PASSPHRASE,
      "--warn-days",
      "99999",
    ]);
    expect(code).toBe(1);
    expect(output()).toContain("WARN");
  });

  it("exits 2 once the certificate is unusable", async () => {
    expect(await main(["check", "fixtures/expired.p12", ...PASSPHRASE])).toBe(2);
    expect(output()).toContain("FAIL");
  });
});

describe("failures a person meets", () => {
  it("names a wrong passphrase rather than a parse error", async () => {
    const code = await main(["inspect", "fixtures/valid-modern.p12", "--passphrase", "wrong"]);
    expect(code).toBe(2);
    expect(output()).toContain("WrongPassphraseError");
  });

  it("names a file that is not a certificate", async () => {
    const code = await main(["inspect", "fixtures/not-a-certificate.p12", ...PASSPHRASE]);
    expect(code).toBe(2);
    expect(output()).toContain("NotPkcs12Error");
  });
});

describe("usage", () => {
  it("lists the environment variables it reads", async () => {
    expect(await main(["env"])).toBe(0);
    expect(output()).toContain("MTLS_PKCS12_BASE64");
    expect(output()).toContain("MTLS_PKCS12_PASSPHRASE");
  });

  it("prints usage and exits 0 when asked for nothing", async () => {
    expect(await main([])).toBe(0);
    expect(output()).toContain("inspect");
  });

  it("exits non-zero on a command it does not have", async () => {
    expect(await main(["frobnicate"])).toBe(1);
  });
});
