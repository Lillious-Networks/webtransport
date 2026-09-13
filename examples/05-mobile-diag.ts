/**
 * Mobile diagnostic for WebTransport on iOS.
 *
 * Tests connection in stages to isolate failure points:
 * 1. HTTP/3 fetch() probe: catches QUIC unreachable
 * 2. WebTransport handshake: catches negotiation failures
 * 3. Data exchange: catches flow control and session issues
 *
 * Captures separate errors from wt.ready and wt.closed since Safari
 * reports different detail on each event.
 *
 *   bun examples/05-mobile-diag.ts [--cert path] [--key path] [--host 0.0.0.0] [--port 443]
 *
 * TLS on iOS:
 * Safari on iOS has no click-through for untrusted certificates, and the
 * full-trust toggle in Settings lists only certificates that are CAs, so a
 * plain self-signed leaf can never work there: the QUIC handshake fails with
 * a certificate_unknown alert however the leaf was installed.
 *
 * So by default this mints a throwaway root CA, signs a leaf covering every
 * LAN address on this machine, and serves the root for installation:
 *
 *   /ca.pem            the CA certificate
 *   /ca.mobileconfig   one-tap install profile for the same CA
 *
 * On the device: install the CA (the .mobileconfig link does it in a tap),
 * then Settings > General > About > Certificate Trust Settings > enable full
 * trust for "WebTransport Diagnostic CA". The CA is cached under
 * ~/.webtransport-diag and reused, so a restart does not invalidate it.
 *
 * Pass --cert <path> --key <path> to use certificates from a real CA instead,
 * and --ca <path> to serve that root for download.
 *
 * Then open on mobile: https://<machine-ip>:<port>/
 * Page reports directly to this process and to the browser.
 */
import { generateCaSigned, serve, signWithCa } from "../js/index.ts";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { networkInterfaces, homedir } from "os";
import { randomUUID } from "crypto";
import { join } from "path";

process.env.RUST_LOG ||= "wt_core=debug";

// Parse CLI args
const args = new Map<string, string>();
let i = 0;
const argv = process.argv.slice(2);
while (i < argv.length) {
  if (argv[i].startsWith("--")) {
    const key = argv[i].slice(2);
    const value = argv[i + 1];
    if (value && !value.startsWith("--")) {
      args.set(key, value);
      i += 2;
    } else {
      i += 1;
    }
  } else {
    i += 1;
  }
}

const certPath = args.get("cert");
const keyPath = args.get("key");
const caPath = args.get("ca");
const bindHost = args.get("host") || "0.0.0.0";
const portArg = args.get("port") ? parseInt(args.get("port")!, 10) : 443;

/**
 * Where the generated CA lives across runs. A device installs the CA once;
 * restarting the server must not mint a new root and force reinstalling it.
 */
const CA_DIR = join(homedir(), ".webtransport-diag");
const CA_CERT_FILE = join(CA_DIR, "ca.pem");
const CA_KEY_FILE = join(CA_DIR, "ca-key.pem");

/**
 * Every IPv4 address this machine answers to. iOS validates the certificate
 * SAN strictly against whatever the user types into Safari, so the cert must
 * cover each one.
 */
function lanAddresses(): string[] {
  const found: string[] = [];
  for (const infos of Object.values(networkInterfaces())) {
    for (const info of infos ?? []) {
      if (info.family === "IPv4" && !info.internal) found.push(info.address);
    }
  }
  return found;
}

/**
 * Drops everything after the first certificate in a PEM chain, keeping the
 * end-entity leaf.
 *
 * Chromium rejects a QUIC chain that carries its own root in-band ("certificate
 * unknown"), and every browser would rather find the root in its own trust
 * store anyway, so send the leaf alone.
 */
function leafOnlyPem(chainPem: string): string {
  return chainPem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n";
}

let cert: string;
let key: string;
let caCert: string | null = null;

const lanIps = lanAddresses();

if (certPath && keyPath) {
  cert = readFileSync(certPath, "utf-8");
  key = readFileSync(keyPath, "utf-8");
  caCert = caPath ? readFileSync(caPath, "utf-8") : null;
  console.log(`Using certificates from ${certPath} and ${keyPath}`);
} else {
  // Mint a root CA and chain the server certificate to it. This is the only
  // shape a stock iPhone can be made to trust without a public CA: iOS offers
  // its full-trust toggle for CAs only, so a self-signed leaf fails the QUIC
  // handshake with certificate_unknown no matter how it was installed.
  const hostnames = ["localhost", "127.0.0.1", ...lanIps];
  if (bindHost !== "0.0.0.0" && bindHost !== "::" && !hostnames.includes(bindHost)) {
    hostnames.push(bindHost);
  }

  if (existsSync(CA_CERT_FILE) && existsSync(CA_KEY_FILE)) {
    const generated = signWithCa(
      hostnames,
      readFileSync(CA_KEY_FILE, "utf-8"),
      readFileSync(CA_CERT_FILE, "utf-8"),
    );
    cert = generated.cert;
    key = generated.key;
    caCert = generated.caCert;
    console.log(`Reusing the CA cached in ${CA_DIR}; devices that trusted it stay trusted.`);
  } else {
    const generated = generateCaSigned(hostnames);
    cert = generated.cert;
    key = generated.key;
    caCert = generated.caCert;
    mkdirSync(CA_DIR, { recursive: true });
    writeFileSync(CA_CERT_FILE, generated.caCert);
    writeFileSync(CA_KEY_FILE, generated.caKey);
    console.log(`Generated a CA-signed certificate covering: ${hostnames.join(", ")}`);
    console.log(`CA cached in ${CA_DIR}; install it once per device.`);
  }

  cert = leafOnlyPem(cert);
}

const WT_PORT = portArg;
const PAGE_PORT = portArg;

/// Per browser diagnostic result
interface Diagnostic {
  name: string;
  http3Probe: { ok: boolean; error?: string; latency?: number };
  wtReady: { ok: boolean; error?: string; latency?: number };
  wtData: { ok: boolean; error?: string };
  wtClosed: { reason?: string; error?: string };
  overallPass: boolean;
}

const diagnostics = new Map<string, Diagnostic>();

/** Strips the PEM armour so the CA can be embedded in an install profile. */
function pemToDerBase64(pem: string): string {
  return pem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s+/g, "");
}

/**
 * iOS configuration profile that installs the CA. Downloading this in Safari
 * opens Settings > Profile Downloaded, and afterwards the certificate appears
 * under Certificate Trust Settings, where full trust can be enabled.
 */
function mobileConfig(caPem: string): string {
  const der = pemToDerBase64(caPem);
  const certUuid = randomUUID();
  const payloadUuid = randomUUID();
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>WebTransport Diagnostic CA.cer</string>
			<key>PayloadContent</key>
			<data>${der}</data>
			<key>PayloadDescription</key>
			<string>Trusts the WebTransport diagnostic server. After installing, enable full trust in Settings > General > About > Certificate Trust Settings.</string>
			<key>PayloadDisplayName</key>
			<string>WebTransport Diagnostic CA</string>
			<key>PayloadIdentifier</key>
			<string>com.webtransport.diag.ca.${certUuid}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>${certUuid}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>WebTransport Diagnostic CA</string>
	<key>PayloadIdentifier</key>
	<string>com.webtransport.diag.${payloadUuid}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>${payloadUuid}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`;
}

// Page server handler
async function pageHandler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  if (url.pathname === "/probe") {
    return new Response("ok", { status: 200 });
  }
  if (caCert) {
    if (url.pathname === "/ca.pem") {
      return new Response(caCert, {
        headers: {
          "content-type": "application/x-pem-file",
          "content-disposition": 'attachment; filename="webtransport-ca.pem"',
        },
      });
    }
    if (url.pathname === "/ca.mobileconfig") {
      return new Response(mobileConfig(caCert), {
        headers: {
          "content-type": "application/x-apple-aspen-config",
          "content-disposition": 'attachment; filename="webtransport-ca.mobileconfig"',
        },
      });
    }
  }
  if (url.pathname === "/report") {
    // Every field is treated as optional. A browser that dies partway through
    // is the case this tool exists to catch, and its half-filled report is the
    // evidence; throwing on a missing stage would discard exactly that.
    let diag: any;
    try {
      diag = await req.json();
    } catch {
      return new Response("bad report", { status: 400 });
    }
    const browser = typeof diag?.browser === "string" ? diag.browser : "unknown";
    const stage = (v: any) => ({ ok: v?.ok === true, error: v?.error, latency: v?.latency });
    const http3 = stage(diag?.http3);
    const wtReady = stage(diag?.wtReady);
    const wtData = stage(diag?.wtData);
    const wtClosed = { reason: diag?.wtClosed?.reason, error: diag?.wtClosed?.error };

    diagnostics.set(browser, {
      name: browser,
      http3Probe: http3,
      wtReady,
      wtData,
      wtClosed,
      overallPass: http3.ok && wtReady.ok && wtData.ok,
    });

    const mark = (v: { ok: boolean }) => (v.ok ? "pass" : "FAIL");
    console.log(
      `${browser}: http3=${mark(http3)} ready=${mark(wtReady)} data=${mark(wtData)}`
    );
    if (http3.error) console.log(`  http3 error: ${http3.error}`);
    if (wtReady.error) console.log(`  ready error: ${wtReady.error}`);
    if (wtData.error) console.log(`  data error: ${wtData.error}`);
    if (wtClosed.reason) console.log(`  closed reason: ${wtClosed.reason}`);
    if (wtClosed.error) console.log(`  closed error: ${wtClosed.error}`);
    return new Response("ok");
  }
  return new Response(page, { headers: { "content-type": "text/html; charset=utf-8" } });
}

// Start HTTPS page server (required for WebTransport)
const pageServer = Bun.serve({
  port: PAGE_PORT,
  hostname: bindHost,
  tls: { cert, key },
  fetch: pageHandler,
});

const wtServer = await serve({
  port: WT_PORT,
  hostname: bindHost,
  cert,
  key,
  maxSessions: 16,
  async session(session, request) {
    const clientInfo = request.headers.get("user-agent") || "unknown";
    console.log(`[WT] session ${request.path} from ${clientInfo}`);

    try {
      // Echo to confirm data flows
      const reader = session.datagrams.readable.getReader();
      const writer = session.datagrams.createWritable().getWriter();
      const { value } = await reader.read();
      await writer.write(new TextEncoder().encode("pong"));
      console.log(`[WT] datagram echo complete`);
    } catch (err: any) {
      console.log(`[WT] session ended: ${err?.message ?? err}`);
    }
  },
  error(err: any) {
    console.log(`[WT Server] error: ${err?.message ?? err}`);
  },
});

function browserName(userAgent: string): string {
  if (userAgent.includes("Safari/") && userAgent.includes("Mobile")) return "safari-ios";
  if (userAgent.includes("Safari/")) return "safari-mac";
  if (userAgent.includes("Firefox/")) return "firefox";
  if (userAgent.includes("Edg/")) return "edge";
  if (userAgent.includes("Chrome/")) return "chrome";
  return "browser";
}

const trustHelp = caCert
  ? `<div class="stage">
<h3>Trust setup</h3>
<pre class="detail">iOS: install the CA via <a href="/ca.mobileconfig">one-tap profile</a>
or <a href="/ca.pem" download>ca.pem</a>, then enable full trust:
Settings &gt; General &gt; About &gt; Certificate Trust Settings &gt;
"WebTransport Diagnostic CA".
You may need to reload this page afterwards.

Desktop Chrome: the server already imports the CA for the current
Windows user; if the page still shows a certificate warning, import
<a href="/ca.pem" download>ca.pem</a> into Trusted Root Certification
Authorities.

WebTransport runs over QUIC/UDP: the HTTP/3 probe above uses TCP, so it
passing does not prove UDP is reachable. If the handshake below fails
with a network error while the server console stays silent, Windows
Firewall is dropping inbound UDP.</pre>
</div>`
  : "";

const page = `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebTransport Mobile Diagnostic</title>
<style>
  body{font:14px/1.5 system-ui;padding:2rem;background:#f9f9f9}
  pre{background:white;padding:1rem;border-radius:6px;border-left:4px solid #ccc;overflow:auto}
  .stage{margin:1rem 0;padding:1rem;border-radius:6px;background:white}
  .stage h3{margin:0 0 0.5rem 0;font-size:16px}
  .ok{border-left-color:#4caf50;color:#4caf50;font-weight:bold}
  .fail{border-left-color:#f44336;color:#f44336;font-weight:bold}
  .pending{border-left-color:#2196f3;color:#2196f3;font-weight:bold}
  .detail{font-size:12px;color:#666;margin-top:0.5rem}
  a{color:#2196f3}
</style>
<h1>WebTransport Mobile Diagnostic</h1>
${trustHelp}
<div id="stages"></div>
<script>
const stages = document.getElementById("stages");

function addStage(name, className) {
  const div = document.createElement("div");
  div.className = "stage";
  div.innerHTML = "<h3 class='" + className + "'>" + name + "</h3><pre id='" + name.replace(/\\s+/g, '_') + "' class='detail'></pre>";
  stages.appendChild(div);
  return div.querySelector("pre");
}

const http3Log = addStage("HTTP/3 Probe", "pending");
const wtReadyLog = addStage("WebTransport Ready", "pending");
const wtDataLog = addStage("Data Exchange", "pending");
const wtClosedLog = addStage("Connection Closed", "pending");

function log(el, msg) {
  el.textContent += (el.textContent ? "\\n" : "") + msg;
}

// Safari puts the useful part in different places depending on the failure,
// so record every field a WebTransportError or DOMException can carry rather
// than just the message.
function describe(err) {
  if (!err) return "unknown error";
  const parts = [];
  const msg = (err.message || String(err)).trim();
  parts.push(msg || err.name || "unknown error");
  if (err.name && err.name !== msg) parts.push("name=" + err.name);
  if (err.source) parts.push("source=" + err.source);
  if (err.streamErrorCode !== undefined && err.streamErrorCode !== null)
    parts.push("streamErrorCode=" + err.streamErrorCode);
  if (err.code) parts.push("code=" + err.code);
  return parts.join(" ");
}

(async () => {
  const start = Date.now();
  const ua = navigator.userAgent;
  const browserName = ua.includes("Safari/") && ua.includes("Mobile")
    ? "safari-ios"
    : ua.includes("Edg/")
    ? "edge"
    : ua.includes("Chrome/")
    ? "chrome"
    : ua.includes("Safari/")
    ? "safari-mac"
    : "browser";

  const result = { http3: {}, wtReady: {}, wtData: {}, wtClosed: {} };

  // Stage 1: HTTP/3 probe (tests QUIC connectivity)
  try {
    const probeStart = Date.now();
    const res = await fetch(location.origin + "/probe", { method: "HEAD" });
    const probeTime = Date.now() - probeStart;
    result.http3 = { ok: true, latency: probeTime };
    log(http3Log, "PASS (" + probeTime + "ms)");
    http3Log.parentElement.querySelector("h3").className = "ok";
  } catch (err) {
    const errorMsg = (err?.message || String(err)).trim();
    result.http3 = { ok: false, error: errorMsg };
    log(http3Log, "FAIL: " + errorMsg);
    if (err?.name) log(http3Log, "Error type: " + err.name);
    http3Log.parentElement.querySelector("h3").className = "fail";
    // Continue despite HTTP/3 failure to test WT separately
  }

  // Stage 2: WebTransport ready
  const wtStart = Date.now();
  // Constructing can throw outright: the API may be absent entirely, or the
  // URL rejected synchronously. That is a result worth reporting, not a
  // reason to abandon the run with a blank page.
  let wt;
  try {
    if (typeof WebTransport === "undefined") {
      throw new Error("WebTransport is not implemented in this browser");
    }
    wt = new WebTransport(location.origin + "/test");
  } catch (err) {
    const fullError = describe(err);
    result.wtReady = { ok: false, error: fullError };
    result.wtData = { ok: false, error: "skipped (constructor threw)" };
    log(wtReadyLog, "FAIL: " + fullError);
    wtReadyLog.parentElement.querySelector("h3").className = "fail";
    await fetch("/report", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ browser: browserName, ...result }),
    }).catch(() => {});
    return;
  }

  let wtReadyError = null;
  wt.ready
    .then(() => {
      const readyTime = Date.now() - wtStart;
      result.wtReady = { ok: true, latency: readyTime };
      log(wtReadyLog, "PASS (" + readyTime + "ms)");
      wtReadyLog.parentElement.querySelector("h3").className = "ok";
    })
    .catch((err) => {
      const fullError = describe(err);
      wtReadyError = fullError;
      result.wtReady = { ok: false, error: fullError };
      log(wtReadyLog, "FAIL: " + fullError);
      if (err?.name) log(wtReadyLog, "Error type: " + err.name);
      wtReadyLog.parentElement.querySelector("h3").className = "fail";
    });

  // Wait for ready or timeout
  await Promise.race([
    wt.ready.catch(() => {}),
    new Promise((r) => setTimeout(r, 5000)),
  ]);

  // Stage 3: Data exchange (if ready)
  if (!wtReadyError) {
    try {
      // The CR replaced datagrams.writable with createWritable(), and
      // browsers sit at different points in that move: Safari has made the
      // switch, Chromium has not. Take whichever this one offers.
      const datagramsWritable =
        typeof wt.datagrams.createWritable === "function"
          ? wt.datagrams.createWritable()
          : wt.datagrams.writable;
      if (!datagramsWritable) throw new Error("no datagram writable on this browser");
      const writer = datagramsWritable.getWriter();
      const reader = wt.datagrams.readable.getReader();
      await writer.write(new TextEncoder().encode("ping"));
      const { value } = await Promise.race([reader.read(), new Promise((r) => setTimeout(() => r({ value: null }), 2000))]);
      if (value) {
        result.wtData = { ok: true };
        log(wtDataLog, "PASS");
        wtDataLog.parentElement.querySelector("h3").className = "ok";
      } else {
        result.wtData = { ok: false, error: "datagram timeout" };
        log(wtDataLog, "FAIL: datagram timeout");
        wtDataLog.parentElement.querySelector("h3").className = "fail";
      }
    } catch (err) {
      const errorMsg = describe(err);
      result.wtData = { ok: false, error: errorMsg };
      log(wtDataLog, "FAIL: " + errorMsg);
      if (err?.name) log(wtDataLog, "Error type: " + err.name);
      wtDataLog.parentElement.querySelector("h3").className = "fail";
    }
  } else {
    result.wtData = { ok: false, error: "skipped (ready failed)" };
    log(wtDataLog, "SKIPPED");
  }

  // Stage 4: Closed event.
  //
  // Awaited before reporting, with a bound so a session that stays open does
  // not stall the run. When ready rejects, Safari routinely puts the actual
  // reason on closed instead, and reporting before it settles would drop the
  // one field worth having.
  const closed = wt.closed
    .then(() => {
      result.wtClosed = { ok: true, reason: "clean close" };
      log(wtClosedLog, "Closed cleanly");
      wtClosedLog.parentElement.querySelector("h3").className = "ok";
    })
    .catch((err) => {
      const errorMsg = describe(err);
      result.wtClosed = { ok: false, error: errorMsg };
      log(wtClosedLog, "Error: " + errorMsg);
      wtClosedLog.parentElement.querySelector("h3").className = "fail";
    });
  // A session that is still open when the timeout wins is the healthy case,
  // not a missing result. Saying so beats leaving the panel blank, which
  // reads as a stage that failed silently.
  const stillOpen = Symbol("open");
  const outcome = await Promise.race([
    closed,
    new Promise((r) => setTimeout(() => r(stillOpen), 3000)),
  ]);
  if (outcome === stillOpen) {
    result.wtClosed = { ok: true, reason: "still open after 3s" };
    log(wtClosedLog, "Still open (the session did not close, which is expected on success)");
    wtClosedLog.parentElement.querySelector("h3").className = "ok";
  }

  // Report to server
  await fetch("/report", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ browser: browserName, ...result }),
  }).catch(() => {});
})();
</script>
`;

const addresses = lanIps.length
  ? lanIps.map((ip) => `  https://${ip}:${PAGE_PORT}/`).join("\n")
  : `  https://<machine-ip>:${PAGE_PORT}/`;

console.log(`
WebTransport diagnostic server
================================
WT server:        https://${bindHost}:${WT_PORT}/
Diagnostic UI:    https://${bindHost}:${PAGE_PORT}/

Access on iOS:
${addresses}

Install the CA on the device first${
  caCert
    ? `:
  one-tap profile:  https://<machine-ip>:${PAGE_PORT}/ca.mobileconfig
  CA PEM:           https://<machine-ip>:${PAGE_PORT}/ca.pem

  Then: Settings > General > About > Certificate Trust Settings >
  enable full trust for "WebTransport Diagnostic CA".`
    : " (no CA available; use --ca <path> to serve one)."
}

Desktop:
  Open https://localhost:${PAGE_PORT}/ in any browser.
${
  certPath
    ? ""
    : `  Chrome has no click-through for WebTransport either, so trust the CA first:
    certutil -user -addstore Root ${CA_CERT_FILE}
  (run it yourself: this installs a root that can sign for any site, so it is
  not something to do behind your back. Remove it with -delstore when done.)
`
}
${certPath ? `Serving the certificate at ${certPath}.` : `Install the CA, then enable full trust for it on the device.`}

Press Ctrl+C to exit.
`);
