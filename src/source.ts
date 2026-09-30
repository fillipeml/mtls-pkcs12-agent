/** Where the certificate comes from.
 *
 * Three places, because deployments differ and the difference is not cosmetic. A file on disk
 * is how a developer holds one. A base64 environment variable is how a platform with no
 * persistent filesystem holds one. Raw bytes are how a service that fetches per-customer
 * certificates from a vault holds one.
 *
 * All three end in the same place — bytes in memory, parsed, key to PEM, PEM into a TLS
 * context — and none of them writes anything. A certificate written to a temporary file to
 * get past an API that only takes paths survives a crash, lands in a container layer, and is
 * readable by anything else running as the same user.
 */
import { readFileSync } from "node:fs";

import { Identity } from "./identity.ts";
import { NotPkcs12Error } from "./errors.ts";

export interface EnvNames {
  /** Base64 of the PKCS#12 file. */
  base64: string;
  /** Path to the PKCS#12 file, used when the base64 variable is empty. */
  path: string;
  passphrase: string;
}

export const DEFAULT_ENV: EnvNames = {
  base64: "MTLS_PKCS12_BASE64",
  path: "MTLS_PKCS12_PATH",
  passphrase: "MTLS_PKCS12_PASSPHRASE",
};

export function fromFile(path: string, passphrase: string): Identity {
  return Identity.fromPkcs12(new Uint8Array(readFileSync(path)), passphrase);
}

export function fromBase64(encoded: string, passphrase: string): Identity {
  return Identity.fromPkcs12(decodeBase64(encoded), passphrase);
}

export function fromBytes(bytes: Uint8Array, passphrase: string): Identity {
  return Identity.fromPkcs12(bytes, passphrase);
}

/** Reads whichever of the variables is set, preferring the inline one.
 *
 *  Base64 first because a platform that has both usually has the path left over from local
 *  development, and the deployed value should win over the developer's leftover. */
export function fromEnv(
  env: NodeJS.ProcessEnv = process.env,
  names: EnvNames = DEFAULT_ENV,
): Identity {
  const passphrase = env[names.passphrase] ?? "";
  const encoded = env[names.base64]?.trim();
  if (encoded) return fromBase64(encoded, passphrase);

  const path = env[names.path]?.trim();
  if (path) return fromFile(path, passphrase);

  throw new NotPkcs12Error(
    `no certificate configured: set ${names.base64} or ${names.path}` +
      (env[names.passphrase] ? "" : `, and ${names.passphrase} if the file has one`),
  );
}

/** True when a certificate is configured, without reading or decrypting it. */
export function isConfigured(
  env: NodeJS.ProcessEnv = process.env,
  names: EnvNames = DEFAULT_ENV,
): boolean {
  return Boolean(env[names.base64]?.trim() || env[names.path]?.trim());
}

function decodeBase64(encoded: string): Uint8Array {
  // Whitespace survives a copy-paste into a platform's secret field, and a PEM header
  // survives somebody pasting the wrong file entirely. Both are worth saying out loud.
  const cleaned = encoded.replace(/\s+/g, "");
  if (cleaned.startsWith("-----BEGIN")) {
    throw new NotPkcs12Error(
      "this value is PEM, not base64 of a PKCS#12 file. Encode the .pfx itself: " +
        "`base64 -w0 certificate.pfx`",
    );
  }
  if (!cleaned) throw new NotPkcs12Error("the base64 value is empty");
  const bytes = Buffer.from(cleaned, "base64");
  if (!bytes.length) throw new NotPkcs12Error("the base64 value decoded to nothing");
  return new Uint8Array(bytes);
}
