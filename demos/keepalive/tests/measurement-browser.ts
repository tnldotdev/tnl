// opt-in loopback fixture for the browser observers, without a tnl deployment.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { gzipSync } from "node:zlib";
import { chromium } from "playwright";
import { observeTurn, visitorProbe } from "./browser-samples.ts";
import { ARTIFACT_PREFIX, digest } from "../src/release.ts";

const html = "<p>served</p>";
const script = "/* fixed release */".repeat(1_000);
const assets = await Promise.all(
  [
    ["/index.html", html],
    ["/app.js", script],
  ].map(async ([path, body]) => {
    assert(path && body);
    const bytes = new TextEncoder().encode(body);
    return { path, size: bytes.length, sha256: await digest(bytes) };
  }),
);
let mode: "ok" | "corrupt" | "unavailable" = "ok";
const server = createServer((req, res) => {
  const url = req.url?.replace(ARTIFACT_PREFIX, "");
  if (url === "/" || url === "/index.html" || url === "/app.js") {
    const data =
      url === "/app.js" ? (mode === "corrupt" ? script.replace("f", "g") : script) : html;
    res.writeHead(mode === "unavailable" ? 503 : 200, {
      "Content-Encoding": "gzip",
      "Content-Type": url === "/app.js" ? "application/javascript" : "text/html",
      "Cache-Control": "no-store",
    });
    res.end(gzipSync(data));
  } else {
    res.writeHead(404);
    res.end();
  }
});
server.listen(0, "127.0.0.1");
await once(server, "listening");
try {
  const address = server.address();
  assert(address && typeof address !== "string");
  const origin = `http://127.0.0.1:${address.port}`;
  const browser = await chromium.launch({ channel: "chrome" });
  try {
    const visitor = await visitorProbe(browser, new URL(origin), assets);
    assert.equal((await visitor.sample()).ok, true);
    mode = "corrupt";
    assert.equal((await visitor.sample()).reason, "integrity");
    mode = "unavailable";
    assert.equal((await visitor.sample()).status, 503);
    await visitor.close();
    mode = "ok";
    const page = await browser.newPage();
    await page.goto(origin);
    const rows: Record<string, unknown>[] = [];
    const [first] = assets;
    assert(first);
    await assert.rejects(
      observeTurn(
        page,
        7,
        { id: "fixture", assets },
        origin,
        first,
        async () => {
          await page.evaluate(
            async (paths) => {
              performance.mark("keepalive volunteered");
              performance.mark("keepalive invited");
              performance.mark("keepalive copying");
              for (const path of paths) await (await fetch(path)).arrayBuffer();
              performance.mark("keepalive copied");
              performance.mark("keepalive ended", { detail: "expired" });
            },
            assets.map((a) => ARTIFACT_PREFIX + a.path),
          );
        },
        (_, fields) => rows.push(fields),
      ),
      /did not publish/,
    );
    const [row] = rows;
    assert(
      row &&
        row.outcome === "expired" &&
        row.verifiedAt === null &&
        row.completeWireSample === true,
    );
    assert(
      typeof row.encodedHttpBytesObserved === "number" &&
        row.encodedHttpBytesObserved > 0 &&
        row.encodedHttpBytesObserved < script.length,
    );
    console.log(
      "loopback Chrome verified page and script, detected corruption and 503, and measured a compressed copy on an expired turn",
    );
  } finally {
    await browser.close();
  }
} finally {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}
