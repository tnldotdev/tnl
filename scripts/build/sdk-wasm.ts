import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";

const exec = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const output = path.join(root, "packages/ts/dist/wasm");
await mkdir(output, { recursive: true });
const { stdout: goroot } = await exec("go", ["env", "GOROOT"], { cwd: root });
const goEnv = { ...process.env, GOOS: "js", GOARCH: "wasm", CGO_ENABLED: "0" };
const wasmPackage = "./packages/ts/wasm";
async function buildModule(file: string, tag: string) {
  const tags = `-tags=${tag}`;
  const { stdout: deps } = await exec("go", ["list", "-deps", tags, wasmPackage], {
    cwd: root,
    env: goEnv,
  });
  // portable runtimes don't start native telemetry exporters.
  const nativeExporters = deps
    .trim()
    .split("\n")
    .filter((name) =>
      /^(go\.opentelemetry\.io\/otel\/(?:exporters|sdk)(?:\/|$)|google\.golang\.org\/(?:grpc|protobuf)(?:\/|$)|github\.com\/prometheus\/)/.test(
        name,
      ),
    );
  if (nativeExporters.length > 0)
    throw new Error(`${file} imports native telemetry dependencies: ${nativeExporters.join(", ")}`);
  const unoptimized = path.join(output, `.${file}.unoptimized`);
  const artifact = path.join(output, file);
  try {
    await exec(
      "go",
      ["build", tags, "-trimpath", "-ldflags=-s -w", "-o", unoptimized, wasmPackage],
      {
        cwd: root,
        env: goEnv,
        maxBuffer: 4 * 1024 * 1024,
      },
    );
    await exec(
      "wasm-opt",
      [
        unoptimized,
        "-Oz",
        "--enable-bulk-memory",
        "--enable-nontrapping-float-to-int",
        "-o",
        artifact,
      ],
      { cwd: root, maxBuffer: 4 * 1024 * 1024 },
    );
  } finally {
    await unlink(unoptimized).catch((error: unknown) => {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
    });
  }
  const bytes = await readFile(artifact);
  return {
    wasmBytes: bytes.byteLength,
    gzipBytes: gzipSync(bytes, { level: 9 }).byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}
// optimize serially to keep peak memory bounded on build runners.
const connector = await buildModule("tnl.wasm", "tnlconnector");
const publisher = await buildModule("publisher.wasm", "tnlpublisher");

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
const manifest = {
  go: version.trim(),
  optimizer: optimizer.trim(),
  modules: { "tnl.wasm": connector, "publisher.wasm": publisher },
};
await writeFile(path.join(output, "build.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify(manifest));
