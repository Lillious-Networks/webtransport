/**
 * Development certificate helper.
 *
 * WebTransport requires TLS even locally. This generates a self-signed
 * certificate and the SHA-256 hash a client passes as `serverCertificateHashes`,
 * which is how a session is trusted without a CA.
 */

import { native } from "./native.js";

/**
 * @param {string[]} [hostnames] defaults to ["localhost"]
 * @returns {{ cert: string, key: string, hash: Uint8Array }}
 */
export function generateSelfSigned(hostnames = ["localhost"]) {
  return native.generateSelfSigned(hostnames);
}
