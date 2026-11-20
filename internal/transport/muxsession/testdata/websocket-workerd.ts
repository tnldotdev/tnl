import { spawn } from "node:child_process";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { stdin } from "node:process";
import { createRequire } from "node:module";
import { build } from "esbuild";
import * as z from "zod";

const chunks: Buffer[] = [];
for await (const chunk of stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
const input = z
  .strictObject({
    server: z.url(),
    hello: z.string(),
    spki: z.string(),
    certificate: z.string(),
    wasm: z.string(),
    wasmExec: z.string(),
  })
  .parse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
const require = createRequire(import.meta.url);
const manifest = z
  .object({ devDependencies: z.object({ workerd: z.string() }) })
  .parse(JSON.parse(await readFile(new URL("../../../../package.json", import.meta.url), "utf8")));
const workerd = z
  .object({ default: z.string(), version: z.literal(manifest.devDependencies.workerd) })
  .parse(require("workerd"));
const directory = await mkdtemp(join(dirname(input.wasm), "workerd-wss-"));
try {
  await writeFile(join(directory, "websocket.wasm"), await readFile(input.wasm));
  await writeFile(join(directory, "fixture.pem"), input.certificate);
  await build({
    stdin: {
      contents: `
        import ${JSON.stringify(input.wasmExec)};
        import wasm from "./websocket.wasm";
        export default {
          async test() {
            const pair = new WebSocketPair();
            pair[0].accept();
            pair[1].accept();
            if (typeof pair[0].bufferedAmount !== "undefined") throw new Error("workerd API changed: requalify bounded sends");
            if (typeof pair[0].send(new Uint8Array(0)) !== "undefined") throw new Error("workerd API changed: requalify asynchronous sends");
            pair[0].close();
            pair[1].close();
            globalThis.tnlWASMEndpoint = ${JSON.stringify(input.server)};
            const go = new Go();
            const instance = await WebAssembly.instantiate(wasm, go.importObject);
            await go.run(instance);
            if (globalThis.tnlWASMResult !== "ok") {
              throw new Error("WASM conformance: " + globalThis.tnlWASMResult);
            }
          }
        };
      `,
      loader: "js",
      resolveDir: process.cwd(),
    },
    bundle: true,
    format: "esm",
    platform: "browser",
    external: ["./websocket.wasm"],
    outfile: join(directory, "worker.js"),
  });
  await writeFile(
    join(directory, "config.capnp"),
    `using Workerd = import "/workerd/workerd.capnp";
     const config :Workerd.Config = (
       services = [
         (name = "test", worker = (
           modules = [
             (name = "worker.js", esModule = embed "worker.js"),
             (name = "websocket.wasm", wasm = embed "websocket.wasm")
           ],
           compatibilityDate = "2026-10-31"
         )),
         (name = "internet", network = (
           allow = ["local"], tlsOptions = (trustedCertificates = [embed "fixture.pem"])
         ))
       ]
     );`,
  );
  const child = spawn(workerd.default, ["test", join(directory, "config.capnp")], {
    timeout: 8000,
    killSignal: "SIGKILL",
  });
  const output: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => output.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => output.push(chunk));
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  if (code !== 0) {
    process.stderr.write(Buffer.concat(output));
    throw new Error(`workerd test exited ${code}`);
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
process.stdout.write("ok\n");
