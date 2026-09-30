/** Reading a PKCS#12 container, including the ones Node refuses.
 *
 * Node can build a TLS context straight from a `.pfx`, so a package that parses one in
 * JavaScript needs a reason. Here it is, reproducible in two commands:
 *
 *     openssl pkcs12 -export -legacy -out legacy.pfx -inkey key.pem -in cert.pem
 *     node -e 'require("tls").createSecureContext({pfx:require("fs").readFileSync("legacy.pfx"),passphrase:"..."})'
 *     # ERR_CRYPTO_UNSUPPORTED_OPERATION: Unsupported PKCS12 PFX data
 *
 * Node 17 and later ship OpenSSL 3, which moved the old PKCS#12 encryption algorithms —
 * RC2-40-CBC above all — into the legacy provider and does not load it by default. Files
 * produced by older tooling are therefore unreadable by Node while remaining perfectly valid,
 * and the error message names neither the algorithm nor the fix. Certificate authorities that
 * issue to end users still hand out files in exactly that shape, so this is not an edge case
 * for anyone integrating with a government or banking API.
 *
 * node-forge implements the ciphers in JavaScript and does not care what OpenSSL will load.
 * The private key never reaches the disk: it is decoded to PEM in memory and handed straight
 * to `tls.createSecureContext`.
 *
 * Verified on Node 24.15 with OpenSSL 3.5.5 on 30 September 2026. `npm test` reproduces both
 * halves — the refusal and the workaround — against generated fixtures.
 */
import forge from "node-forge";

import {
  IncompleteIdentityError,
  NotPkcs12Error,
  WrongPassphraseError,
} from "./errors.ts";

/** The parts of a PKCS#12 that a TLS identity is made of. */
export interface Pkcs12Contents {
  /** The leaf certificate, PEM encoded. */
  certificatePem: string;
  /** The private key, PEM encoded. Never written anywhere by this package. */
  privateKeyPem: string;
  /** Any intermediate certificates the file carried, leaf first. */
  chainPem: string[];
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: Date;
  notAfter: Date;
  /** SHA-256 of the leaf certificate's DER, lowercase hex. Identifies it without exposing it. */
  fingerprint: string;
}

const CERT_BAG = forge.pki.oids.certBag as string;
const SHROUDED_BAG = forge.pki.oids.pkcs8ShroudedKeyBag as string;
const PLAIN_BAG = forge.pki.oids.keyBag as string;

/** The message node-forge produces for a bad MAC, which is what a wrong passphrase looks like. */
const WRONG_PASSPHRASE_HINTS = ["invalid password", "mac", "integrity"];

/** Parses the container. `passphrase` may be empty, which some issuers use. */
export function readPkcs12(bytes: Uint8Array, passphrase: string): Pkcs12Contents {
  const container = open(bytes, passphrase);

  const certificates = bagsOf(container, CERT_BAG)
    .map((bag) => bag.cert)
    .filter((cert): cert is forge.pki.Certificate => Boolean(cert));
  const key =
    bagsOf(container, SHROUDED_BAG).find((bag) => bag.key)?.key ??
    bagsOf(container, PLAIN_BAG).find((bag) => bag.key)?.key;

  if (!certificates.length) {
    throw new IncompleteIdentityError(
      "the PKCS#12 file holds no certificate. A file exported as 'certificate only' or one " +
        "holding only a CA chain looks like this.",
    );
  }
  if (!key) {
    throw new IncompleteIdentityError(
      "the PKCS#12 file holds no private key, so it cannot authenticate anything. This is " +
        "what an export without the key produces, and it is a common mistake in certificate " +
        "manager dialogues.",
    );
  }

  const leaf = pickLeaf(certificates);
  const chain = certificates.filter((cert) => cert !== leaf);

  return {
    certificatePem: forge.pki.certificateToPem(leaf),
    privateKeyPem: forge.pki.privateKeyToPem(key),
    chainPem: chain.map((cert) => forge.pki.certificateToPem(cert)),
    subject: describe(leaf.subject.attributes),
    issuer: describe(leaf.issuer.attributes),
    serialNumber: leaf.serialNumber,
    notBefore: leaf.validity.notBefore,
    notAfter: leaf.validity.notAfter,
    fingerprint: fingerprintOf(leaf),
  };
}

function open(bytes: Uint8Array, passphrase: string): forge.pkcs12.Pkcs12Pfx {
  let asn1: forge.asn1.Asn1;
  try {
    asn1 = forge.asn1.fromDer(forge.util.createBuffer(toBinary(bytes)));
  } catch (error) {
    throw new NotPkcs12Error(
      "these bytes are not DER-encoded, so they are not a PKCS#12 file. A PEM bundle or a " +
        `base64 string that was not decoded first looks like this. (${message(error)})`,
    );
  }
  try {
    return forge.pkcs12.pkcs12FromAsn1(asn1, passphrase);
  } catch (error) {
    const text = message(error).toLowerCase();
    if (WRONG_PASSPHRASE_HINTS.some((hint) => text.includes(hint))) {
      throw new WrongPassphraseError();
    }
    throw new NotPkcs12Error(`the PKCS#12 container could not be read: ${message(error)}`);
  }
}

function bagsOf(container: forge.pkcs12.Pkcs12Pfx, oid: string): forge.pkcs12.Bag[] {
  return container.getBags({ bagType: oid })[oid] ?? [];
}

/** The leaf is the certificate that is not an issuer of any other certificate present.
 *
 *  Bag order is not guaranteed, and taking the first one gets the chain the wrong way round
 *  on files where the CA happens to be stored first — which then fails the handshake with an
 *  error about the wrong certificate being presented. */
function pickLeaf(certificates: forge.pki.Certificate[]): forge.pki.Certificate {
  if (certificates.length === 1) return certificates[0]!;
  const subjects = new Set(certificates.map((cert) => describe(cert.subject.attributes)));
  const leaves = certificates.filter(
    (cert) =>
      !certificates.some(
        (other) =>
          other !== cert &&
          describe(other.issuer.attributes) === describe(cert.subject.attributes),
      ),
  );
  if (leaves.length === 1) return leaves[0]!;
  // Ambiguous, which happens with a self-signed pair: fall back to the first, deterministically.
  void subjects;
  return leaves[0] ?? certificates[0]!;
}

function describe(attributes: forge.pki.CertificateField[]): string {
  return attributes
    .map((attribute) => `${attribute.shortName ?? attribute.name ?? "?"}=${String(attribute.value)}`)
    .join(", ");
}

function fingerprintOf(certificate: forge.pki.Certificate): string {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(certificate)).getBytes();
  const digest = forge.md.sha256.create();
  digest.update(der);
  return digest.digest().toHex();
}

function toBinary(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
}

function message(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "object" && error !== null && "message" in error) {
    return String((error as { message: unknown }).message);
  }
  return String(error);
}
