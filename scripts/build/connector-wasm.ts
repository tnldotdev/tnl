import { execFile } from "node:child_process";
import { copyFile, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const exec = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const output = path.join(root, "development/connector-wasm/dist");
const started = performance.now();

await mkdir(output, { recursive: true });
const { stdout: goroot } = await exec("go", ["env", "GOROOT"], { cwd: root });
await exec(
  "go",
  [
    "build",
    "-trimpath",
    "-ldflags=-s -w",
    "-o",
    path.join(output, "connector.wasm"),
    "./development/connector-wasm/go",
  ],
  { cwd: root, env: { ...process.env, GOOS: "js", GOARCH: "wasm", CGO_ENABLED: "0" } },
);
await copyFile(
  path.join(goroot.trim(), "lib/wasm/wasm_exec.js"),
  path.join(output, "wasm_exec.js"),
);
await copyFile(path.join(goroot.trim(), "LICENSE"), path.join(output, "go-license.txt"));

const { stdout: goVersion } = await exec("go", ["version"], { cwd: root });
const { stdout: quicVersion } = await exec("go", ["list", "-m", "github.com/quic-go/quic-go"], {
  cwd: root,
});
const { size: wasmBytes } = await stat(path.join(output, "connector.wasm"));
const versions = JSON.parse(await readFile(path.join(root, "package.json"), "utf8")) as {
  devDependencies: Record<string, string>;
};
const result = {
  go: goVersion.trim(),
  quic: quicVersion.trim(),
  workerd: versions.devDependencies.workerd,
  wasmBytes,
  buildMilliseconds: performance.now() - started,
};
await writeFile(path.join(output, "build.json"), `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify(result));
