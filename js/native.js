/**
 * Loads the native addon.
 *
 * Bun >= 1.4 only: no Node or Deno fallbacks by design.
 */

import { createRequire } from "node:module";
import { copyFileSync, existsSync, statSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

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
function cargoDirs() {
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
function candidates() {
  const { platform, arch } = process;
  const abi = platform === "linux" && isMusl() ? "musl" : platform === "linux" ? "gnu" : null;
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

function libraryName() {
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
 * @param {string} path
 */
function nodeAlias(path) {
  const alias = join(root, "wt.node");
  try {
    const source = statSync(path);
    const existing = existsSync(alias) ? statSync(alias) : null;
    // Refresh a stale alias so a rebuild is picked up.
    if (!existing || existing.mtimeMs < source.mtimeMs) {
      copyFileSync(path, alias);
    }
  } catch {
    // If the copy fails, fall back to the original path and let require report
    // whatever the real problem is.
    return path;
  }
  return alias;
}

function isMusl() {
  try {
    // glibc reports itself in the report; musl builds do not.
    return !process.report?.getReport?.()?.header?.glibcVersionRuntime;
  } catch {
    return false;
  }
}

function load() {
  const tried = [];
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
        `Found the WebTransport addon at ${path} but could not load it: ${err.message}`,
        { cause: err },
      );
    }
  }
  throw new Error(
    "Could not find the native WebTransport addon. Build it with `bun run build`.\n" +
      `Looked in:\n${tried.map((p) => `  ${p}`).join("\n")}`,
  );
}

export const native = load();

// Closes the QUIC endpoints before the addon's Tokio runtime is torn down at
// process exit. Without it a live endpoint driver is dropped mid-flight and
// the process aborts, turning a clean run into a non-zero exit with nothing in
// the output to explain it.
native.installExitHook();

// The exit event fires before teardown begins, unlike the napi cleanup hook
// above, which Bun runs while the environment is already being destroyed.
// Closing from here lets the settle wait in closeAllEndpoints() actually run,
// so everything parked on the endpoints (accepts, reads, closed waiters)
// resolves while the runtime still exists.
process.on("exit", () => {
  native.closeAllEndpoints();
});
