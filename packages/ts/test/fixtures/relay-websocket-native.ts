import { stdin } from "node:process";
import * as z from "zod";
import { build } from "esbuild";
import { chromium } from "playwright";
import type { relayWebSocketProbe } from "./relay-websocket-probe.ts";

const chunks: Buffer[] = [];
for await (const chunk of stdin) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
const input = z
  .strictObject({
    server: z.url(),
    hello: z.string(),
    spki: z.string().regex(/^[A-Za-z0-9+/]{43}=$/),
  })
  .parse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
const bundle = await build({
  entryPoints: [new URL("./relay-websocket-probe.ts", import.meta.url).pathname],
  bundle: true,
  write: false,
  format: "iife",
  globalName: "relayProbe",
  platform: "browser",
});
const source = bundle.outputFiles[0];
if (!source) throw new Error("relay probe bundle is missing");
// pin only this disposable fixture's leaf key; never change browser trust stores.
const browser = await chromium.launch({
  channel: "chrome",
  args: [`--ignore-certificate-errors-spki-list=${input.spki}`],
});
try {
  const page = await browser.newPage();
  await page.addScriptTag({ content: source.text });
  await page.evaluate(async ({ server, hello }) => {
    const probe = (
      globalThis as unknown as { relayProbe: { relayWebSocketProbe: typeof relayWebSocketProbe } }
    ).relayProbe;
    await probe.relayWebSocketProbe(
      new WebSocket(server, "tnl-yamux-v1"),
      Uint8Array.from(atob(hello), (c) => c.charCodeAt(0)),
      AbortSignal.timeout(5000),
    );
  }, input);
} finally {
  await browser.close();
}
process.stdout.write("ok\n");
