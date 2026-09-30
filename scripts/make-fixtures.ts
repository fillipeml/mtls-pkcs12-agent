/** Generates the certificate fixtures.
 *
 * Self-signed, two days of validity by default, and entirely synthetic — a fixture that is a
 * real certificate is a real certificate in a public repository. The files are generated
 * rather than committed as opaque blobs so anyone can see exactly what they contain and
 * regenerate them.
 *
 * The legacy file is the interesting one. It has to be built by the `openssl` binary, because
 * the algorithm that matters — pbeWithSHA1And40BitRC2-CBC — is one no JavaScript library
 * writes any more, which is rather the point: it is the algorithm OpenSSL 3 moved into its
 * legacy provider and will not load, and the algorithm certificate authorities were still
 * exporting long after that. `npm test` asserts both halves, Node's refusal and this
 * package's success.
 *
 * That one file is the only place anything here touches a temporary key on disk, and it is a
 * throwaway key generated seconds earlier for a fixture. The library itself never does.
 *
 *   npm run fixtures
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import forge from "node-forge";

const OUT = "fixtures";
const PASSPHRASE = "fixture-passphrase";

/** Fixed so a regenerated fixture differs only where it is meant to. */
const NOT_BEFORE = new Date(Date.UTC(2026, 0, 1));

interface Spec {
  name: string;
  commonName: string;
  notBefore: Date;
  notAfter: Date;
  legacy: boolean;
  passphrase?: string;
}

const YEAR = 365 * 24 * 60 * 60 * 1000;
const DAY = 24 * 60 * 60 * 1000;

const SPECS: Spec[] = [
  {
    name: "valid-modern.p12",
    commonName: "Example Integration Client",
    notBefore: NOT_BEFORE,
    notAfter: new Date(NOT_BEFORE.getTime() + 40 * YEAR),
    legacy: false,
  },
  {
    // The whole reason this package exists: Node cannot open this one.
    name: "valid-legacy.p12",
    commonName: "Example Legacy Client",
    notBefore: NOT_BEFORE,
    notAfter: new Date(NOT_BEFORE.getTime() + 40 * YEAR),
    legacy: true,
  },
  {
    name: "expired.p12",
    commonName: "Example Expired Client",
    notBefore: NOT_BEFORE,
    notAfter: new Date(NOT_BEFORE.getTime() + 10 * DAY),
    legacy: false,
  },
  {
    name: "not-yet-valid.p12",
    commonName: "Example Future Client",
    notBefore: new Date(Date.UTC(2099, 0, 1)),
    notAfter: new Date(Date.UTC(2099, 11, 31)),
    legacy: false,
  },
  {
    name: "no-passphrase.p12",
    commonName: "Example Unprotected Client",
    notBefore: NOT_BEFORE,
    notAfter: new Date(NOT_BEFORE.getTime() + 40 * YEAR),
    legacy: false,
    passphrase: "",
  },
];

function makeCertificate(spec: Spec): {
  certificate: forge.pki.Certificate;
  privateKey: forge.pki.rsa.PrivateKey;
} {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = "01" + Buffer.from(spec.name).toString("hex").slice(0, 16);
  certificate.validity.notBefore = spec.notBefore;
  certificate.validity.notAfter = spec.notAfter;

  const attributes = [
    { name: "commonName", value: spec.commonName },
    { name: "organizationName", value: "Example Organisation" },
    { name: "countryName", value: "ZZ" },
  ];
  certificate.setSubject(attributes);
  certificate.setIssuer(attributes);
  certificate.setExtensions([
    { name: "basicConstraints", cA: false },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", clientAuth: true },
  ]);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  return { certificate, privateKey: keys.privateKey };
}

function toPkcs12(
  certificate: forge.pki.Certificate,
  privateKey: forge.pki.rsa.PrivateKey,
  passphrase: string,
): Uint8Array {
  const asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, [certificate], passphrase, {
    algorithm: "aes256",
  });
  return toBytes(forge.asn1.toDer(asn1).getBytes());
}

/** The RC2-encrypted file, via the openssl binary. Returns null when openssl is unavailable. */
function toLegacyPkcs12(
  certificate: forge.pki.Certificate,
  privateKey: forge.pki.rsa.PrivateKey,
  passphrase: string,
): Uint8Array | null {
  const scratch = mkdtempSync(join(tmpdir(), "mtls-fixture-"));
  try {
    const certPath = join(scratch, "cert.pem");
    const keyPath = join(scratch, "key.pem");
    const outPath = join(scratch, "legacy.p12");
    writeFileSync(certPath, forge.pki.certificateToPem(certificate));
    writeFileSync(keyPath, forge.pki.privateKeyToPem(privateKey));
    execFileSync(
      "openssl",
      ["pkcs12", "-export", "-legacy", "-out", outPath, "-inkey", keyPath, "-in", certPath,
       "-passout", `pass:${passphrase}`],
      { stdio: "pipe" },
    );
    return new Uint8Array(readFileSync(outPath));
  } catch (error) {
    process.stderr.write(
      `could not build the legacy fixture with openssl: ${error instanceof Error ? error.message : error}
`,
    );
    return null;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function toBytes(binary: string): Uint8Array {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 0xff;
  return bytes;
}

function main(): void {
  mkdirSync(OUT, { recursive: true });
  for (const spec of SPECS) {
    const { certificate, privateKey } = makeCertificate(spec);
    const passphrase = spec.passphrase ?? PASSPHRASE;
    const bytes = spec.legacy
      ? toLegacyPkcs12(certificate, privateKey, passphrase)
      : toPkcs12(certificate, privateKey, passphrase);
    if (!bytes) {
      process.stdout.write(`${spec.name.padEnd(22)} SKIPPED (openssl unavailable)\n`);
      continue;
    }
    writeFileSync(join(OUT, spec.name), bytes);
    process.stdout.write(
      `${spec.name.padEnd(22)} ${String(bytes.length).padStart(5)} bytes  ` +
        `${spec.legacy ? "RC2-40-CBC" : "aes256    "}  ` +
        `valid to ${spec.notAfter.toISOString().slice(0, 10)}\n`,
    );
  }

  // A file that is not a PKCS#12 at all, for the "wrong file" path.
  writeFileSync(join(OUT, "not-a-certificate.p12"), "this is not a certificate\n");
  process.stdout.write("not-a-certificate.p12  a text file, for the wrong-file path\n");
}

main();
