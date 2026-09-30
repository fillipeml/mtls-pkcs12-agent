/** A loaded certificate, and how long it has left.
 *
 * The expiry check is the part worth having. A client certificate issued to an organisation
 * typically lasts a year, and it expires while nothing is being deployed — so the first sign
 * is a handshake failing in production one morning, with an error from the far side that says
 * nothing about dates. Anything that can turn that into a warning weeks earlier is worth more
 * than it costs.
 *
 * Nothing here is written to disk, and nothing that could identify the key appears in a
 * `toString`, a `JSON.stringify` or a log line. The fingerprint is the handle: it names a
 * certificate uniquely without revealing anything usable.
 */
import { CertificateExpiredError } from "./errors.ts";
import { readPkcs12, type Pkcs12Contents } from "./pkcs12.ts";

/** Warn once a certificate is inside this window. Roughly a renewal cycle's notice. */
export const DEFAULT_WARN_DAYS = 30;

const MS_PER_DAY = 24 * 60 * 60 * 1000;

export interface IdentitySummary {
  subject: string;
  issuer: string;
  serialNumber: string;
  fingerprint: string;
  notBefore: string;
  notAfter: string;
  daysUntilExpiry: number;
  chainLength: number;
  status: "usable" | "expiring" | "expired" | "not yet valid";
}

export class Identity {
  readonly certificatePem: string;
  readonly privateKeyPem: string;
  readonly chainPem: readonly string[];
  readonly subject: string;
  readonly issuer: string;
  readonly serialNumber: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly fingerprint: string;

  constructor(contents: Pkcs12Contents) {
    this.certificatePem = contents.certificatePem;
    this.privateKeyPem = contents.privateKeyPem;
    this.chainPem = Object.freeze([...contents.chainPem]);
    this.subject = contents.subject;
    this.issuer = contents.issuer;
    this.serialNumber = contents.serialNumber;
    this.notBefore = contents.notBefore;
    this.notAfter = contents.notAfter;
    this.fingerprint = contents.fingerprint;
  }

  static fromPkcs12(bytes: Uint8Array, passphrase: string): Identity {
    return new Identity(readPkcs12(bytes, passphrase));
  }

  /** Whole days until the certificate stops working. Negative once it has. */
  daysUntilExpiry(now: Date = new Date()): number {
    return Math.floor((this.notAfter.getTime() - now.getTime()) / MS_PER_DAY);
  }

  isExpired(now: Date = new Date()): boolean {
    return now.getTime() > this.notAfter.getTime();
  }

  isNotYetValid(now: Date = new Date()): boolean {
    return now.getTime() < this.notBefore.getTime();
  }

  isUsable(now: Date = new Date()): boolean {
    return !this.isExpired(now) && !this.isNotYetValid(now);
  }

  /** The warning to print, or null. Returned rather than logged: a library does not own stderr. */
  expiryWarning(now: Date = new Date(), warnDays: number = DEFAULT_WARN_DAYS): string | null {
    if (this.isExpired(now)) {
      return `the certificate expired on ${iso(this.notAfter)} and no handshake using it will succeed`;
    }
    if (this.isNotYetValid(now)) {
      return `the certificate is not valid until ${iso(this.notBefore)}`;
    }
    const days = this.daysUntilExpiry(now);
    if (days <= warnDays) {
      return `the certificate expires on ${iso(this.notAfter)}, in ${days} day${days === 1 ? "" : "s"}`;
    }
    return null;
  }

  /** Throws unless the certificate is inside its validity window.
   *
   *  Called before a connection is attempted, so the failure names the date rather than
   *  arriving as a handshake error from the far side. */
  assertUsable(now: Date = new Date()): void {
    if (this.isExpired(now)) {
      throw new CertificateExpiredError(
        `the certificate expired on ${iso(this.notAfter)} (${-this.daysUntilExpiry(now)} days ago). ` +
          "A renewed file has to be installed; nothing in this process can work around it.",
        this.notBefore,
        this.notAfter,
      );
    }
    if (this.isNotYetValid(now)) {
      throw new CertificateExpiredError(
        `the certificate is not valid until ${iso(this.notBefore)}. Check the clock on this ` +
          "machine before assuming the file is wrong: a skewed clock produces this exactly.",
        this.notBefore,
        this.notAfter,
      );
    }
  }

  summary(now: Date = new Date()): IdentitySummary {
    return {
      subject: this.subject,
      issuer: this.issuer,
      serialNumber: this.serialNumber,
      fingerprint: this.fingerprint,
      notBefore: iso(this.notBefore),
      notAfter: iso(this.notAfter),
      daysUntilExpiry: this.daysUntilExpiry(now),
      chainLength: this.chainPem.length,
      status: this.isExpired(now)
        ? "expired"
        : this.isNotYetValid(now)
          ? "not yet valid"
          : this.daysUntilExpiry(now) <= DEFAULT_WARN_DAYS
            ? "expiring"
            : "usable",
    };
  }

  /** Neither the key nor the certificate appears here, on purpose. */
  toString(): string {
    return `Identity(${this.subject}, expires ${iso(this.notAfter)}, ${this.fingerprint.slice(0, 16)}…)`;
  }

  toJSON(): IdentitySummary {
    return this.summary();
  }
}

function iso(date: Date): string {
  return date.toISOString().slice(0, 10);
}
