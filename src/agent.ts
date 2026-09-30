/** Turning an identity into an HTTPS agent.
 *
 * The important thing this module does is refuse to do one thing quietly.
 *
 * `rejectUnauthorized: false` is the standard fix for "unable to verify the first
 * certificate", it appears in every forum answer, and it disables verification of the server
 * — which is the half of TLS that stops you handing a client certificate to whoever answered
 * the DNS query. On an mTLS connection that is worse than usual: the whole point of the
 * client certificate is to prove who you are, and with verification off you may be proving it
 * to somebody else.
 *
 * The real cause is almost always a server that does not send its intermediate certificate,
 * and the real fix is to supply the CA yourself. So this package takes `caPem`, and its
 * escape hatch is spelled `dangerouslyDisableServerVerification`, must be passed explicitly,
 * and calls the `onInsecure` hook every time an agent is built with it.
 */
import https from "node:https";

import { Identity } from "./identity.ts";

export interface AgentOptions {
  /** Extra CAs to trust, PEM encoded. The right answer to "unable to verify the first certificate". */
  caPem?: string | string[];
  /** Include the intermediates from the PKCS#12 in what is presented to the server. */
  sendChain?: boolean;
  /** Passed through to Node. */
  keepAlive?: boolean;
  timeoutMs?: number;
  servername?: string;
  minVersion?: "TLSv1.2" | "TLSv1.3";
  /** Refuse to build an agent from a certificate outside its validity window. */
  requireValidDates?: boolean;
  now?: Date;
  /** Called when the certificate is close to expiry, or when verification is disabled. */
  onWarning?: (message: string) => void;
  /**
   * Turns off verification of the **server's** certificate.
   *
   * Named this way because the short name is what makes it easy to reach for. It is almost
   * never the right fix: a server that does not send its intermediate is fixed by passing
   * `caPem`, not by trusting everything. Leaving it on in production means this client will
   * present its certificate to any host that answers.
   */
  dangerouslyDisableServerVerification?: boolean;
}

/** Builds an `https.Agent` that authenticates with this identity. */
export function createAgent(identity: Identity, options: AgentOptions = {}): https.Agent {
  const now = options.now ?? new Date();

  if (options.requireValidDates ?? true) {
    identity.assertUsable(now);
  }

  const warning = identity.expiryWarning(now);
  if (warning && options.onWarning) options.onWarning(warning);

  if (options.dangerouslyDisableServerVerification) {
    options.onWarning?.(
      "server certificate verification is DISABLED for this agent. The client certificate " +
        "will be presented to whatever host answers, which is what an mTLS connection exists " +
        "to prevent. Pass caPem with the server's issuing chain instead.",
    );
  }

  const cert = options.sendChain
    ? [identity.certificatePem, ...identity.chainPem].join("\n")
    : identity.certificatePem;

  return new https.Agent({
    cert,
    key: identity.privateKeyPem,
    ca: options.caPem,
    rejectUnauthorized: !options.dangerouslyDisableServerVerification,
    keepAlive: options.keepAlive ?? true,
    timeout: options.timeoutMs,
    servername: options.servername,
    minVersion: options.minVersion ?? "TLSv1.2",
  });
}

/** Agents by certificate fingerprint.
 *
 *  An agent holds a TLS session cache, so reusing one is worth real latency. Keying on the
 *  fingerprint rather than on a path or a tenant id is the point: in a service that holds a
 *  certificate per customer, a cache keyed on anything else is one refactor away from handing
 *  one customer's identity to another customer's request, and that failure is silent.
 */
export class AgentCache {
  private readonly agents = new Map<string, https.Agent>();

  private readonly options: AgentOptions;

  constructor(options: AgentOptions = {}) {
    this.options = options;
  }

  get(identity: Identity, overrides: AgentOptions = {}): https.Agent {
    const key = `${identity.fingerprint}:${JSON.stringify({ ...this.options, ...overrides, onWarning: undefined, now: undefined })}`;
    const existing = this.agents.get(key);
    if (existing) return existing;
    const agent = createAgent(identity, { ...this.options, ...overrides });
    this.agents.set(key, agent);
    return agent;
  }

  get size(): number {
    return this.agents.size;
  }

  /** Destroys every pooled socket. Call it when a certificate is replaced. */
  clear(): void {
    for (const agent of this.agents.values()) agent.destroy();
    this.agents.clear();
  }
}
