/** Failures, named, because each one sends you somewhere different.
 *
 * A PKCS#12 that will not open has three plausible causes — the wrong passphrase, a file that
 * is not a PKCS#12 at all, and an encryption algorithm the reader cannot handle — and they
 * look identical in a generic parse error. Separating them is most of the value of this
 * module: the first is a typo, the second is the wrong file, and the third is the reason this
 * package exists.
 */

export class Pkcs12Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Pkcs12Error";
  }
}

/** The passphrase did not decrypt the file. */
export class WrongPassphraseError extends Pkcs12Error {
  constructor(message = "the passphrase did not open this PKCS#12 file") {
    super(message);
    this.name = "WrongPassphraseError";
  }
}

/** The bytes are not a PKCS#12 container. */
export class NotPkcs12Error extends Pkcs12Error {
  constructor(message: string) {
    super(message);
    this.name = "NotPkcs12Error";
  }
}

/** The container opened but did not hold what a TLS identity needs. */
export class IncompleteIdentityError extends Pkcs12Error {
  constructor(message: string) {
    super(message);
    this.name = "IncompleteIdentityError";
  }
}

/** The certificate is outside its validity window.
 *
 *  Its own class because it is the failure that arrives on a date rather than on a change: a
 *  one-year certificate expires while nothing was deployed, and the first symptom is a
 *  handshake failing in production on a Tuesday morning. */
export class CertificateExpiredError extends Pkcs12Error {
  readonly notBefore: Date;
  readonly notAfter: Date;

  constructor(message: string, notBefore: Date, notAfter: Date) {
    super(message);
    this.name = "CertificateExpiredError";
    this.notBefore = notBefore;
    this.notAfter = notAfter;
  }
}
