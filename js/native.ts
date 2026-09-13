/**
 * Loads the native addon.
 *
 * Bun >= 1.4 only: no Node or Deno fallbacks by design.
 */

import { createRequire } from "node:module";
import { copyFileSync, existsSync, rmSync, statSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type * as Addon from "../crates/wt-napi/index.d.ts";

/**
 * A native session.
 *
 * The generated declaration types the datagram pump's callback as taking no
 * arguments, because napi-rs cannot describe a threadsafe function's payload.
 * It is called with one packed batch, so that signature is restated here.
 */
export type NativeSession = Omit<Addon.WebTransportSession, "startDatagramPump"> & {
  startDatagramPump(callback: (packed: Uint8Array) => void): void;
};

/** An incoming session, whose `accept` yields the corrected session type. */
export type NativeIncomingSession = Omit<Addon.IncomingSession, "accept"> & {
  accept(): NativeSession;
};

/** A listening server, whose `accept` yields the corrected incoming type. */
export type NativeServer = Omit<Addon.WebTransportServer, "accept"> & {
  accept(): Promise<NativeIncomingSession | null | undefined>;
};

/**
 * The addon's exports.
 *
 * As napi-rs declares them, except where a session is produced: those return
 * the corrected types above. The correction is applied here, where the untyped
 * `require` result first acquires a type, so no other module needs a cast.
 */
export type NativeModule = Omit<typeof Addon, "connect" | "WebTransportServer"> & {
  connect(url: string, options?: Addon.JsClientOptions | null): Promise<NativeSession>;
  WebTransportServer: { bind(options: Addon.JsServerOptions): Promise<NativeServer> };
};
export type NativeBidiStream = Addon.WtBidiStream;
export type NativeRecvStream = Addon.WtRecvStream;
export type NativeSendStream = Addon.WtSendStream;

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

/**
 * Cargo's per-triple output directories, which `napi build --platform` uses.
 *
 * Listed before the root alias because a rebuilt addon cannot overwrite the
 * alias while a process has it loaded: the fresh dll sits in `target/` and
 * only becomes the alias once it is newer. Ordering these first means a dev
 * rebuild is picked up on the next load instead of being silently shadowed.
 */
function cargoDirs(): string[] {
  try {
    return readdirSync(join(root, "target"), { withFileTypes: true })
      .filter((d) => d.isDirectory() && d.name !== "release" && d.name !== "debug")
      .flatMap((d) => [
        join(root, "target", d.name, "release", libraryName()),
        join(root, "target", d.name, "debug", libraryName()),
      ]);
  } catch {
    return [];
  }
}

/** Candidate locations, most specific first. */
function candidates(): string[] {
  const { platform, arch } = process;
  // The suffix has to match the published prebuild names exactly. Linux
  // distinguishes its C library, and Windows carries the toolchain: the
  // release workflow ships wt.win32-x64-msvc.node, so a bare win32-x64 finds
  // nothing. macOS has no suffix.
  const abi =
    platform === "linux" ? (isMusl() ? "musl" : "gnu") : platform === "win32" ? "msvc" : null;
  const triple = abi ? `${platform}-${arch}-${abi}` : `${platform}-${arch}`;

  return [
    // A published prebuild for this platform.
    join(root, `wt.${triple}.node`),
    join(root, "npm", triple, "wt.node"),
    // Locally built artifacts, per-triple output before the shared alias.
    ...cargoDirs(),
    join(root, "wt.node"),
    join(root, "target", "release", libraryName()),
    join(root, "target", "debug", libraryName()),
  ];
}

function libraryName(): string {
  switch (process.platform) {
    case "win32":
      return "wt_napi.dll";
    case "darwin":
      return "libwt_napi.dylib";
    default:
      return "libwt_napi.so";
  }
}

/**
 * Returns a .node path for a cargo-built library, creating it if needed.
 *
 * On Windows a loaded addon is locked, so a server still running from an
 * earlier build holds `wt.node` open and the refresh copy fails with EBUSY.
 * Returning the .dll in that case only trades one failure for a worse one,
 * since require cannot load a library that is not named .node. So fall back
 * to a build-stamped alias, which a running process is never holding.
 */
function nodeAlias(path: string): string {
  let source;
  try {
    source = statSync(path);
  } catch {
    return path;
  }
  const stamped = `wt.${Math.floor(source.mtimeMs).toString(36)}.node`;
  for (const name of ["wt.node", stamped]) {
    const alias = join(root, name);
    try {
      const existing = existsSync(alias) ? statSync(alias) : null;
      // Refresh a stale alias so a rebuild is picked up.
      if (!existing || existing.mtimeMs < source.mtimeMs) {
        copyFileSync(path, alias);
      }
      sweepStaleAliases(name === stamped ? stamped : null);
      return alias;
    } catch {
      // Locked by another process: try the next name.
    }
  }
  // Nothing worked, so let require report the real problem against the
  // original path.
  return path;
}

/**
 * Deletes build-stamped aliases other than `keep`.
 *
 * Each rebuild taken while an older server still holds `wt.node` leaves
 * another multi-megabyte copy behind, so without this they accumulate
 * silently. One still loaded by a live process cannot be deleted, which is
 * exactly the one that must survive: the failure is the desired outcome.
 *
 * @param keep the stamped alias in use, if any
 */
function sweepStaleAliases(keep: string | null): void {
  try {
    for (const name of readdirSync(root)) {
      if (name === keep || name === "wt.node") continue;
      if (!/^wt\.[a-z0-9]+\.node$/.test(name)) continue;
      try {
        rmSync(join(root, name));
      } catch {
        // In use by another process, which is reason enough to keep it.
      }
    }
  } catch {
    // Listing the directory is best effort.
  }
}

function isMusl(): boolean {
  try {
    // glibc reports itself in the report; musl builds do not. The report's
    // declared type is an opaque object, so the one field read is named here.
    const report = process.report?.getReport?.() as
      | { header?: { glibcVersionRuntime?: string } }
      | undefined;
    return !report?.header?.glibcVersionRuntime;
  } catch {
    return false;
  }
}

function load(): NativeModule {
  const tried: string[] = [];
  for (const path of candidates()) {
    tried.push(path);
    if (!existsSync(path)) continue;
    // A napi addon must be required through a .node path. Cargo emits a
    // platform-native name (.dll/.so/.dylib), so link a .node alias next to it
    // rather than making every developer copy the file by hand.
    const loadable = path.endsWith(".node") ? path : nodeAlias(path);
    try {
      return require(loadable);
    } catch (err) {
      throw new Error(
        `Found the WebTransport addon at ${path} but could not load it: ${(err as Error).message}`,
        { cause: err },
      );
    }
  }
  throw new Error(
    "Could not find the native WebTransport addon. Build it with `bun run build`.\n" +
      `Looked in:\n${tried.map((p) => `  ${p}`).join("\n")}`,
  );
}

export const native: NativeModule = load();
