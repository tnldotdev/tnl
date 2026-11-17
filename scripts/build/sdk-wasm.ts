import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, stat, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";

const exec = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const output = path.join(root, "packages/ts/dist/wasm");
const unoptimized = path.join(output, ".tnl.unoptimized.wasm");

await mkdir(output, { recursive: true });
const { stdout: goroot } = await exec("go", ["env", "GOROOT"], { cwd: root });
try {
  await exec(
    "go",
    ["build", "-trimpath", "-ldflags=-s -w", "-o", unoptimized, "./packages/ts/wasm"],
    {
      cwd: root,
      env: { ...process.env, GOOS: "js", GOARCH: "wasm", CGO_ENABLED: "0" },
      maxBuffer: 4 * 1024 * 1024,
    },
  );
  // keep the complete Go engine while reducing the deployed module's raw size.
  await exec(
    "wasm-opt",
    [
      unoptimized,
      "-Oz",
      "--enable-bulk-memory",
      "--enable-nontrapping-float-to-int",
      "-o",
      path.join(output, "tnl.wasm"),
    ],
    { cwd: root, maxBuffer: 4 * 1024 * 1024 },
  );
} finally {
  await unlink(unoptimized).catch((error: unknown) => {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
  });
}
// ship the runtime from the same toolchain that compiled the module.
await copyFile(
  path.join(goroot.trim(), "lib/wasm/wasm_exec.js"),
  path.join(output, "wasm_exec.js"),
);
await writeFile(path.join(output, "wasm_exec.d.ts"), "export {};\n");
await copyFile(path.join(goroot.trim(), "LICENSE"), path.join(output, "go-license.txt"));
await copyFile(
  path.join(root, "THIRD_PARTY_LICENSES.txt"),
  path.join(output, "third-party-licenses.txt"),
);
const { stdout: version } = await exec("go", ["version"], { cwd: root });
const { stdout: optimizer } = await exec("wasm-opt", ["--version"], { cwd: root });
const bytes = await readFile(path.join(output, "tnl.wasm"));
const manifest = {
  go: version.trim(),
  optimizer: optimizer.trim(),
  wasmBytes: (await stat(path.join(output, "tnl.wasm"))).size,
  gzipBytes: gzipSync(bytes, { level: 9 }).byteLength,
  sha256: createHash("sha256").update(bytes).digest("hex"),
};
await writeFile(path.join(output, "build.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify(manifest));
