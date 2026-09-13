/**
 * Development certificate helper.
 *
 * WebTransport requires TLS even locally. This generates a self-signed
 * certificate and the SHA-256 hash a client passes as `serverCertificateHashes`,
 * which is how a session is trusted without a CA.
 */

import { native } from "./native.ts";

export interface SelfSignedCertificate {
  cert: string;
  key: string;
  hash: Uint8Array;
}

export interface CaSignedCertificate extends SelfSignedCertificate {
  caCert: string;
  caKey: string;
}

/** @param hostnames populates the SAN; defaults to ["localhost"] */
export function generateSelfSigned(hostnames: string[] = ["localhost"]): SelfSignedCertificate {
  return native.generateSelfSigned(hostnames);
}

/**
 * Mints a throwaway root CA and a server certificate signed by it.
 *
 * Safari on iOS has no click-through for an untrusted certificate, and its
 * full-trust toggle lists only CAs, so a self-signed leaf cannot be used there
 * however it is installed: the QUIC handshake fails with a certificate_unknown
 * alert. Installing the returned root and enabling full trust for it is the
 * only way to reach a local server from a stock device.
 *
 * Serve `cert` alone. Browsers chain it to the root they now trust, and
 * Chromium rejects a QUIC chain that carries its own root in-band.
 *
 * @param hostnames every name and IP the server answers to
 */
export function generateCaSigned(hostnames: string[] = ["localhost"]): CaSignedCertificate {
  return native.generateCaSigned(hostnames);
}

/**
 * Signs a fresh server certificate with a CA from `generateCaSigned`.
 *
 * Restarting the server must not mint a new root: a device that installed and
 * trusted the old one would have to repeat the whole dance.
 */
export function signWithCa(
  hostnames: string[],
  caKeyPem: string,
  caCertPem: string,
): CaSignedCertificate {
  return native.signWithCa(hostnames, caKeyPem, caCertPem);
}
