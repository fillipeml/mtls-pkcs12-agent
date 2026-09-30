/** A command line for the questions you have at three in the morning.
 *
 * All of them are the same question in different words: is it the certificate? Every command
 * here answers some part of that without a deployment, and none of them prints the key.
 */
import { readFileSync } from "node:fs";
import https from "node:https";

import { createAgent } from "./agent.ts";
import { CertificateExpiredError, Pkcs12Error } from "./errors.ts";
import { Identity } from "./identity.ts";
import { fromBase64, fromBytes, DEFAULT_ENV } from "./source.ts";

const out = (line = ""): void => {
  process.stdout.write(`${line}\n`);
};

function load(path: string, passphrase: string): Identity {
  return fromBytes(new Uint8Array(readFileSync(path)), passphrase);
}

/** What is in the file, and how long it has left. */
function inspect(path: string, passphrase: string): number {
  const identity = load(path, passphrase);
  const summary = identity.summary();
  out(`subject      ${summary.subject}`);
  out(`issuer       ${summary.issuer}`);
  out(`serial       ${summary.serialNumber}`);
  out(`fingerprint  ${summary.fingerprint}`);
  out(`valid        ${summary.notBefore} to ${summary.notAfter}`);
  out(`chain        ${summary.chainLength} intermediate certificate(s) in the file`);
  out(`status       ${summary.status}, ${summary.daysUntilExpiry} day(s) left`);

  const warning = identity.expiryWarning();
  if (warning) out(`\n! ${warning}`);
  return summary.status === "usable" || summary.status === "expiring" ? 0 : 1;
}

/** Exit non-zero when the certificate is unusable or close to it. For a cron job. */
function check(path: string, passphrase: string, warnDays: number): number {
  const identity = load(path, passphrase);
  const days = identity.daysUntilExpiry();
  if (!identity.isUsable()) {
    out(`FAIL  ${identity.subject}: ${identity.expiryWarning()}`);
    return 2;
  }
  if (days <= warnDays) {
    out(`WARN  ${identity.subject}: expires in ${days} day(s), on ${identity.notAfter.toISOString().slice(0, 10)}`);
    return 1;
  }
  out(`OK    ${identity.subject}: ${days} day(s) left`);
  return 0;
}

/** Does Node accept this file on its own? The question this package exists to answer. */
async function compare(path: string, passphrase: string): Promise<number> {
  const bytes = new Uint8Array(readFileSync(path));
  const tls = await import("node:tls");

  let nodeAccepts = true;
  let nodeError = "";
  try {
    tls.createSecureContext({ pfx: Buffer.from(bytes), passphrase });
  } catch (error) {
    nodeAccepts = false;
    nodeError = error instanceof Error ? `${(error as NodeJS.ErrnoException).code ?? ""} ${error.message}`.trim() : String(error);
  }

  let hereAccepts = true;
  let hereError = "";
  try {
    fromBytes(bytes, passphrase);
  } catch (error) {
    hereAccepts = false;
    hereError = error instanceof Error ? error.message : String(error);
  }

  out(`node's own PKCS#12 reader : ${nodeAccepts ? "accepts it" : `REFUSES it — ${nodeError}`}`);
  out(`this package              : ${hereAccepts ? "accepts it" : `refuses it — ${hereError}`}`);
  if (!nodeAccepts && hereAccepts) {
    out("");
    out("This is the case the package is for. Node ships OpenSSL 3, which moved the older");
    out("PKCS#12 encryption algorithms into a legacy provider it does not load, so a file");
    out("that is perfectly valid becomes unreadable. Nothing is wrong with the certificate.");
  }
  return hereAccepts ? 0 : 1;
}

/** Make one request with the certificate, and say what came back. */
async function probe(url: string, path: string, passphrase: string, caPath?: string): Promise<number> {
  const identity = load(path, passphrase);
  const agent = createAgent(identity, {
    caPem: caPath ? readFileSync(caPath, "utf8") : undefined,
    onWarning: (message) => out(`! ${message}`),
  });

  out(`presenting ${identity.subject}`);
  out(`to         ${url}`);
  out("");

  return new Promise((resolve) => {
    const request = https.request(url, { agent, method: "GET" }, (response) => {
      let body = "";
      response.on("data", (chunk) => {
        body += String(chunk);
      });
      response.on("end", () => {
        out(`HTTP ${response.statusCode}`);
        if (body) out(body.slice(0, 400));
        resolve(response.statusCode && response.statusCode < 400 ? 0 : 1);
      });
    });
    request.on("error", (error) => {
      const code = (error as NodeJS.ErrnoException).code ?? "";
      out(`connection failed: ${code} ${error.message}`);
      if (code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" || code === "SELF_SIGNED_CERT_IN_CHAIN") {
        out("");
        out("That is the SERVER's certificate failing to verify, not yours. The usual cause is");
        out("a server that does not send its intermediate. Pass --ca with the issuing chain.");
        out("Turning verification off would also silence it, and would mean presenting your");
        out("client certificate to whatever host answers.");
      }
      resolve(1);
    });
    request.end();
  });
}

const USAGE = `mtls-pkcs12-agent

  inspect <file> [--passphrase P]       what is in the certificate, and how long it has left
  check   <file> [--passphrase P] [--warn-days N]
                                        exit 0 usable, 1 expiring, 2 unusable. For a cron job
  compare <file> [--passphrase P]       whether node accepts this file on its own
  probe   <url> --cert <file> [--passphrase P] [--ca <file>]
                                        one request with the certificate, with the likely
                                        cause named if the handshake fails
  env                                   the environment variables this package reads

The passphrase may also come from ${DEFAULT_ENV.passphrase}. Nothing here prints the private key.
`;

function flag(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(`--${name}`);
  return index === -1 ? undefined : argv[index + 1];
}

export async function main(argv: string[]): Promise<number> {
  const [command, first] = argv;
  const passphrase = flag(argv, "passphrase") ?? process.env[DEFAULT_ENV.passphrase] ?? "";

  try {
    switch (command) {
      case "inspect":
        if (!first) break;
        return inspect(first, passphrase);
      case "check": {
        if (!first) break;
        const warnDays = Number(flag(argv, "warn-days") ?? 30);
        return check(first, passphrase, Number.isFinite(warnDays) ? warnDays : 30);
      }
      case "compare":
        if (!first) break;
        return await compare(first, passphrase);
      case "probe": {
        const cert = flag(argv, "cert");
        if (!first || !cert) break;
        return await probe(first, cert, passphrase, flag(argv, "ca"));
      }
      case "env":
        out(`${DEFAULT_ENV.base64}      base64 of the PKCS#12 file, for a host with no filesystem`);
        out(`${DEFAULT_ENV.path}        path to the PKCS#12 file`);
        out(`${DEFAULT_ENV.passphrase}  the passphrase, if the file has one`);
        return 0;
      default:
        break;
    }
  } catch (error) {
    if (error instanceof CertificateExpiredError || error instanceof Pkcs12Error) {
      process.stderr.write(`${error.name}: ${error.message}\n`);
      return 2;
    }
    throw error;
  }

  out(USAGE);
  return command ? 1 : 0;
}

/** Only used by the tests; exported so a caller can build an identity from an env var. */
export { fromBase64 };

if (import.meta.filename === process.argv[1]) {
  process.exitCode = await main(process.argv.slice(2));
}
