import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { chromium, type Browser } from "playwright";
import { afterAll, beforeAll, expect, test } from "vitest";
import type * as fixture from "../helpers/publisher-browser.js";

declare global {
  interface Window {
    portablePublicationTest: typeof fixture;
  }
}

let browser: Browser;
let origin: string;
let source: string;
const server = createServer((_request, reply) => {
  reply.writeHead(200, { "Content-Type": "text/html" }).end("<!doctype html>");
});

beforeAll(async () => {
  const result = await build({
    entryPoints: [fileURLToPath(new URL("../helpers/publisher-browser.ts", import.meta.url))],
    bundle: true,
    write: false,
    format: "iife",
    globalName: "portablePublicationTest",
    platform: "browser",
    plugins: [
      {
        name: "go-publication-boundary",
        setup(builder) {
          builder.onResolve({ filter: /\/wasm_loader\.js$/ }, () => ({
            path: fileURLToPath(new URL("../helpers/publisher-loader.ts", import.meta.url)),
          }));
        },
      },
    ],
  });
  source = result.outputFiles[0]?.text ?? "";
  if (source === "") throw new Error("missing browser fixture");
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing fixture listener");
  origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch({ channel: "chrome" });
});

afterAll(async () => {
  await browser?.close();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
});

test("automatic browser publishing uses real default IndexedDB storage across fresh tabs", async () => {
  const context = await browser.newContext();
  try {
    const first = await context.newPage();
    await first.goto(origin);
    await first.addScriptTag({ content: source });
    expect(
      await first.evaluate(() => window.portablePublicationTest.exerciseBrowserPublication()),
    ).toEqual({ restored: [], applicationResponse: "browser handler" });
    const second = await context.newPage();
    await second.goto(origin);
    await second.addScriptTag({ content: source });
    expect(
      await second.evaluate(() => window.portablePublicationTest.exerciseBrowserPublication()),
    ).toEqual({ restored: [1, 2, 3], applicationResponse: "browser handler" });
  } finally {
    await context.close();
  }
});
