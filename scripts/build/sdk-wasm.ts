import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import { buildGoWasm, goWasmEnv, sdkWasmPackage } from "./go-wasm.ts";

const exec = promisify(execFile);
const root = path.resolve(import.meta.dirname, "../..");
const output = path.join(root, "packages/ts/dist/wasm");
await mkdir(output, { recursive: true });
const { stdout: goroot } = await exec("go", ["env", "GOROOT"], { cwd: root });
async function buildModule(file: string, tag: string) {
  // tnlsdk excludes telemetry schema validation. the second tag selects the
  // connector or publisher bridge so browser consumers can load them separately.
  const tags = `tnlsdk,${tag}`;
  const { stdout: deps } = await exec("go", ["list", "-deps", `-tags=${tags}`, sdkWasmPackage], {
    cwd: root,
    env: { ...process.env, ...goWasmEnv },
  });
  // check dependencies before linking. runtime template lookup can keep unused
  // methods on unrelated types, so the SDK uses fixed markup instead.
  const nativeDependencies = deps
    .trim()
    .split("\n")
    .filter((name) =>
      /^(go\.opentelemetry\.io\/otel\/(?:exporters|sdk)(?:\/|$)|google\.golang\.org\/(?:grpc|protobuf)(?:\/|$)|github\.com\/(?:prometheus|pion)\/|github\.com\/(?:alecthomas\/kong|santhosh-tekuri\/jsonschema)(?:\/|$)|go\.yaml\.in\/yaml\/|(?:html|text)\/template(?:\/|$)|net\/http\/pprof$)/.test(
        name,
      ),
    );
  if (nativeDependencies.length > 0)
    throw new Error(`${file} imports native-only dependencies: ${nativeDependencies.join(", ")}`);
  const artifact = path.join(output, file);
  await buildGoWasm({ cwd: root, tags, output: artifact });
  const bytes = await readFile(artifact);
  // the portable publisher needs the shared control client, not its demo and
  // feedback methods. go list cannot distinguish them; check function names in
  // the runtime stack tables, which survive -s -w and wasm-opt.
  const nativeControl = [
    "CreateServiceRunPreview",
    "AuthorizeReviewerFeedback",
    "AuthorizeImplementerFeedback",
    "CreateGuestDemo",
    "AllocateGuestDemoService",
    "EnrollGuestPublisher",
  ].filter((operation) =>
    bytes.includes(`github.com/tnldotdev/tnl/pkg/api/control/public/v1.(*Client).${operation}`),
  );
  if (nativeControl.length > 0)
    throw new Error(`${file} links native-only control calls: ${nativeControl.join(", ")}`);
  return {
    wasmBytes: bytes.byteLength,
    gzipBytes: gzipSync(bytes, { level: 9 }).byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}
// optimize serially to keep peak memory bounded on build runners.
const connector = await buildModule("connector.wasm", "tnlconnector");
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
  modules: { "connector.wasm": connector, "publisher.wasm": publisher },
};
await writeFile(path.join(output, "build.json"), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(JSON.stringify(manifest));
