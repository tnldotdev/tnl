import { readFile } from "node:fs/promises";
import { stdin } from "node:process";
import { chromium } from "playwright";
import * as z from "zod";

const chunks: Buffer[] = [];
for await (const chunk of stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
const input = z
  .strictObject({
    server: z.url(),
    hello: z.string(),
    spki: z.string().regex(/^[A-Za-z0-9+/]{43}=$/),
    wasm: z.string(),
    wasmExec: z.string(),
  })
  .parse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
const wasm = await readFile(input.wasm);
// pin only this disposable fixture's leaf key; never change browser trust stores.
const browser = await chromium.launch({
  channel: "chrome",
  args: [`--ignore-certificate-errors-spki-list=${input.spki}`],
});
try {
  const page = await browser.newPage();
  await page.addScriptTag({ path: input.wasmExec });
  await page.evaluate(
    async ({ server, bytes }) => {
      type GoRuntime = {
        importObject: WebAssembly.Imports;
        run(instance: WebAssembly.Instance): Promise<void>;
      };
      const host = globalThis as unknown as {
        Go: new () => GoRuntime;
        tnlWASMEndpoint: string;
        tnlWASMResult?: string;
      };
      host.tnlWASMEndpoint = server;
      const go = new host.Go();
      const binary = Uint8Array.from(atob(bytes), (c) => c.charCodeAt(0));
      const { instance } = await WebAssembly.instantiate(binary, go.importObject);
      await go.run(instance);
      if (host.tnlWASMResult !== "ok") {
        throw new Error(`WASM transport conformance: ${host.tnlWASMResult ?? "no result"}`);
      }
    },
    { server: input.server, bytes: wasm.toString("base64") },
  );
} finally {
  await browser.close();
}
process.stdout.write("ok\n");
