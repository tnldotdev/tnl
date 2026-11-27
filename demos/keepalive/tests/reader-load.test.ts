import { createServer } from "node:http";
import { once } from "node:events";
import { gzipSync } from "node:zlib";
import { expect, it } from "vitest";
import { digest } from "../src/release.ts";
import { readerConnections, readerOpen, type ReaderTransfer } from "./reader-load.ts";
import { vi } from "vitest";

it("verifies compressed bytes and makes connection reuse observable", async () => {
  const bytes = new TextEncoder().encode("fixed release\n".repeat(100));
  const asset = { path: "/app.js", size: bytes.length, sha256: await digest(bytes) };
  let mode: "ok" | "corrupt" | "unavailable" = "ok";
  const server = createServer((_req, res) => {
    res.writeHead(mode === "unavailable" ? 503 : 200, {
      "Content-Encoding": "gzip",
      "X-Keepalive-Run": "expected",
    });
    res.end(gzipSync(mode === "corrupt" ? bytes.slice().fill(1) : bytes));
  });
  const listening = once(server, "listening");
  server.listen(0, "127.0.0.1");
  await listening;
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture has no port");
  const url = new URL(`http://127.0.0.1:${address.port}`);
  const connections = readerConnections(true, 1);
  const samples: ReaderTransfer[] = [];
  const open = () =>
    readerOpen(
      connections,
      url,
      [asset],
      new AbortController().signal,
      (sample) => samples.push(sample),
      "expected",
    );
  try {
    expect((await open()).ok).toBe(true);
    expect((await open()).ok).toBe(true);
    expect(samples[0]?.reused).toBe(false);
    expect(samples[1]?.reused).toBe(true);
    const warnings = vi.spyOn(process, "emitWarning");
    for (let i = 0; i < 15; i++) expect((await open()).ok).toBe(true);
    expect(warnings).not.toHaveBeenCalled();
    expect(samples[0]?.decodedBytes).toBe(bytes.length);
    expect(samples[0]?.encodedBodyBytes).toBeLessThan(bytes.length);
    mode = "corrupt";
    expect(await open()).toMatchObject({ ok: false, reason: "integrity" });
    mode = "unavailable";
    expect(await open()).toMatchObject({ ok: false, reason: "upstream_status" });
  } finally {
    connections.close();
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});

it("fresh mode closes sockets, rejects changed runs, and joins canceled reads", async () => {
  const bytes = new Uint8Array([1]);
  const asset = { path: "/app.js", size: 1, sha256: await digest(bytes) };
  let mode: "ok" | "stall" = "ok";
  const server = createServer((_req, res) => {
    res.writeHead(200, { "X-Keepalive-Run": "actual" });
    if (mode === "ok") res.end(bytes);
    else res.flushHeaders();
  });
  const listening = once(server, "listening");
  server.listen(0, "127.0.0.1");
  await listening;
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture has no port");
  const url = new URL(`http://127.0.0.1:${address.port}`);
  const connections = readerConnections(false, 1);
  try {
    const signal = new AbortController().signal;
    expect((await connections.transfer(url, asset, asset.path, signal)).reused).toBe(false);
    expect((await connections.transfer(url, asset, asset.path, signal)).reused).toBe(false);
    expect(await connections.transfer(url, asset, asset.path, signal, "other")).toMatchObject({
      ok: false,
      reason: "service_run_changed",
    });
    mode = "stall";
    const abort = new AbortController();
    const pending = connections.transfer(url, asset, asset.path, abort.signal);
    abort.abort();
    expect(await pending).toMatchObject({ ok: false, reason: "deadline_or_canceled" });
  } finally {
    connections.close();
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
