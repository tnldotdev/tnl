// opt-in loopback proof of the public load task, report, and HTTP connection modes.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import * as z from "zod/mini";
import { digest } from "../src/release.ts";

const directory = await mkdtemp(join(tmpdir(), "keepalive-reader-load-"));
const bodies = new Map([
  ["/index.html", "<p>fixed page</p>"],
  ["/app.js", "/* fixed script */".repeat(1_000)],
  ["/hosting/worker.js", "/* worker fixture */"],
  ["/hosting/wasm/publisher.wasm", "wasm fixture"],
]);
const assets = await Promise.all(
  [...bodies].map(async ([path, text]) => {
    const bytes = new TextEncoder().encode(text);
    return { path, size: bytes.length, sha256: await digest(bytes) };
  }),
);
const release = {
  id: await digest(new TextEncoder().encode(JSON.stringify(assets))),
  assets,
};
const manifest = join(directory, "release.json");
await writeFile(manifest, JSON.stringify(release), { flag: "wx", mode: 0o600 });
let mode: "ok" | "corrupt" = "ok";
const server = createServer((req, res) => {
  const body = bodies.get(req.url === "/" ? "/index.html" : (req.url ?? ""));
  if (body === undefined) {
    res.writeHead(404);
    res.end();
    return;
  }
  res.writeHead(200, { "Content-Encoding": "gzip" });
  res.end(
    gzipSync(mode === "corrupt" && req.url === "/app.js" ? body.replace("fixed", "wrong") : body),
  );
});
const listening = once(server, "listening");
server.listen(0, "127.0.0.1");
await listening;
const address = server.address();
assert(address && typeof address !== "string");
const site = `http://127.0.0.1:${address.port}`;
const stage = z.object({
  event: z.string(),
  successful: z.optional(z.number()),
  failed: z.optional(z.number()),
  scheduled: z.optional(z.number()),
  reused: z.optional(z.boolean()),
  complete: z.optional(z.boolean()),
  passed: z.optional(z.boolean()),
  reason: z.optional(z.string()),
  result: z.optional(z.object({ ok: z.boolean(), reason: z.string() })),
});
async function run(
  name: string,
  connections: string,
  rates = "1,5,10",
  seconds = "2",
  passing = true,
) {
  const report = join(directory, `${name}.ndjson`);
  const child = spawn(
    "task",
    [
      "js:keepalive:load:readers",
      `SITE=${site}`,
      `MANIFEST=${manifest}`,
      `RELEASE=${release.id}`,
      `REPORT=${report}`,
      `RATES=${rates}`,
      `SECONDS=${seconds}`,
      `CONNECTIONS=${connections}`,
    ],
    { stdio: "inherit" },
  );
  const [code] = await once(child, "exit");
  assert.equal(code === 0, passing, "unexpected reader task outcome");
  return (await readFile(report, "utf8"))
    .trim()
    .split("\n")
    .map((line) => stage.parse(JSON.parse(line)));
}
try {
  const fresh = await run("fresh", "fresh");
  assert(fresh.filter((row) => row.event === "transfer").every((row) => !row.reused));
  const reused = await run("reused", "reuse");
  assert(reused.some((row) => row.event === "transfer" && row.reused));
  for (const rows of [fresh, reused]) {
    assert.equal(rows.filter((row) => row.event === "arrival").length, 32);
    assert(
      rows
        .filter((row) => row.event === "stage_result")
        .every((row) => row.successful === row.scheduled),
    );
    assert(rows.some((row) => row.event === "end" && row.complete));
  }
  mode = "corrupt";
  const corrupt = await run("corrupt", "fresh", "2", "2", false);
  assert(
    corrupt
      .filter((row) => row.event === "stage_result")
      .every((row) => row.successful === 0 && row.failed === row.scheduled),
  );
  assert(corrupt.some((row) => row.event === "arrival" && row.result?.reason === "integrity"));
  assert(corrupt.some((row) => row.event === "end" && row.complete && row.passed === false));
  console.log(
    `reader task verified fresh/reused connections and counted corrupt transfers: ${directory}`,
  );
} finally {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}
