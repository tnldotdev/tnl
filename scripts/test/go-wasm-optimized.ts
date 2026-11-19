import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";

// go test -exec supplies its compiled binary and test arguments after the mode.
const mode = process.argv[2];
const binary = process.argv[3];
assert(mode === "node" || mode === "chrome", "select node or chrome");
assert(binary, "go-wasm-optimized requires a Go/WASM test binary");
const root = path.resolve(import.meta.dirname, "../..");
const directory = await mkdtemp(path.join(tmpdir(), "tnl-wasm-test-"));
const lifetime = new AbortController();
let active: ChildProcess | undefined;
const stop = () => {
  lifetime.abort();
  const child = active;
  child?.kill("SIGTERM");
  if (child !== undefined) {
    const force = setTimeout(() => child.kill("SIGKILL"), 5000);
    force.unref();
    child.once("close", () => clearTimeout(force));
  }
};
process.once("SIGINT", stop);
process.once("SIGTERM", stop);
try {
  const output = path.join(directory, "test.wasm");
  const optimizing = promisify(execFile)(
    "wasm-opt",
    [binary, "-Oz", "--enable-bulk-memory", "--enable-nontrapping-float-to-int", "-o", output],
    { signal: lifetime.signal },
  );
  active = optimizing.child;
  await optimizing;
  const { stdout: goroot } = await promisify(execFile)("go", ["env", "GOROOT"]);
  lifetime.signal.throwIfAborted();
  const child = spawn(
    mode === "node" ? path.join(goroot.trim(), "lib/wasm/go_js_wasm_exec") : process.execPath,
    [
      ...(mode === "chrome" ? [path.join(root, "scripts/test/go-wasm-browser.ts")] : []),
      output,
      ...process.argv.slice(4),
    ],
    { stdio: "inherit", signal: lifetime.signal },
  );
  active = child;
  process.exitCode = await new Promise<number>((resolve, reject) => {
    let failure: Error | undefined;
    child.once("error", (error) => {
      failure = error;
    });
    child.once("close", (code) => {
      if (failure !== undefined) reject(failure);
      else resolve(code ?? 1);
    });
  });
} finally {
  process.removeListener("SIGINT", stop);
  process.removeListener("SIGTERM", stop);
  await rm(directory, { recursive: true, force: true });
}
