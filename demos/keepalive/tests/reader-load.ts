import * as http from "node:http";
import * as https from "node:https";
import { createGunzip } from "node:zlib";
import { Readable } from "node:stream";
import { TLSSocket } from "node:tls";
import { readAssetResponse, type Asset } from "../src/release.ts";

export type ReaderTransfer = {
  path: string;
  status: number | null;
  reused: boolean;
  tcpMs: number | null;
  tlsMs: number | null;
  tlsResumed: boolean | null;
  headersMs: number | null;
  totalMs: number;
  encodedBodyBytes: number;
  decodedBytes: number;
  ok: boolean;
  reason: string;
  errorCode: string | null;
  runID: string | null;
};

// core HTTP agents make fresh/reused connections explicit. this generator uses
// HTTP/1.1; real Chrome witnesses cover browser HTTP/2 and page execution.
export function readerConnections(reuse: boolean, sockets: number) {
  if (!Number.isSafeInteger(sockets) || sockets < 1 || sockets > 8_192)
    throw new Error("invalid reader socket limit");
  const agents = {
    "http:": new http.Agent({ keepAlive: reuse, maxSockets: sockets, maxFreeSockets: sockets }),
    "https:": new https.Agent({ keepAlive: reuse, maxSockets: sockets, maxFreeSockets: sockets }),
  };
  return {
    async transfer(
      origin: URL,
      asset: Asset,
      path: string,
      signal: AbortSignal,
      expectedRunID?: string,
    ): Promise<ReaderTransfer> {
      const started = performance.now();
      let status: number | null = null;
      let reused = false;
      let tcpMs: number | null = null;
      let tlsMs: number | null = null;
      let tlsResumed: boolean | null = null;
      let headersMs: number | null = null;
      let encodedBodyBytes = 0;
      let decodedBytes = 0;
      let runID: string | null = null;
      let ok = false;
      let reason = "unknown";
      let errorCode: string | null = null;
      try {
        const url = new URL(path, origin);
        const protocol = url.protocol;
        if (protocol !== "http:" && protocol !== "https:") throw new Error("invalid protocol");
        let response: http.IncomingMessage | undefined;
        const incoming = await new Promise<http.IncomingMessage>((resolve, reject) => {
          const request = (protocol === "https:" ? https.request : http.request)(
            url,
            {
              agent: agents[protocol],
              signal,
              headers: { "Accept-Encoding": "gzip", "Cache-Control": "no-store" },
            },
            (incoming) => {
              headersMs = performance.now() - started;
              response = incoming;
              resolve(incoming);
            },
          );
          request.on("socket", (socket) => {
            reused = request.reusedSocket;
            if (reused) return;
            socket.once("connect", () => {
              tcpMs = performance.now() - started;
            });
            if (socket instanceof TLSSocket)
              socket.once("secureConnect", () => {
                tlsMs = performance.now() - started;
                tlsResumed = socket.isSessionReused();
              });
          });
          request.on("error", (error) => {
            if (response && !response.readableEnded) response.destroy(error);
            reject(error);
          });
          request.end();
        });
        status = incoming.statusCode ?? null;
        const reportedRun = incoming.headers["x-keepalive-run"];
        runID = typeof reportedRun === "string" ? reportedRun : null;
        const encoding = incoming.headers["content-encoding"];
        incoming.on("data", (chunk: Buffer) => {
          encodedBodyBytes += chunk.byteLength;
        });
        const body = encoding === "gzip" ? incoming.pipe(createGunzip()) : incoming;
        const failed = (error: Error) => {
          body.destroy(error);
        };
        incoming.on("error", failed);
        // invalid statuses can be rejected before toWeb attaches its listeners.
        body.on("error", () => {});
        try {
          if (status !== 200 || (expectedRunID && runID !== expectedRunID))
            throw new Error(status !== 200 ? "upstream_status" : "service_run_changed");
          if (encoding !== undefined && encoding !== "gzip")
            throw new Error("unsupported_encoding");
          const payload = new Response(Readable.toWeb(body) as ReadableStream<Uint8Array>);
          const bytes = await readAssetResponse(asset, payload, signal);
          signal.throwIfAborted();
          decodedBytes = bytes.byteLength;
        } finally {
          incoming.off("error", failed);
          if (!incoming.complete) incoming.destroy();
          if (!body.readableEnded) body.destroy();
        }
        ok = true;
        reason = "verified";
      } catch (error) {
        if (
          error instanceof Error &&
          "code" in error &&
          typeof error.code === "string" &&
          /^E[A-Z0-9_]{1,40}$/.test(error.code)
        )
          errorCode = error.code;
        reason = signal.aborted
          ? "deadline_or_canceled"
          : error instanceof Error
            ? error.message
            : "unknown";
        // never put remote error text or arbitrary exception messages in a report.
        if (
          ![
            "upstream_status",
            "service_run_changed",
            "unsupported_encoding",
            "deadline_or_canceled",
          ].includes(reason)
        )
          reason =
            error instanceof Error &&
            [
              "Response does not match the release.",
              "Response size does not match.",
              "Response exceeds limit.",
            ].includes(error.message)
              ? "integrity"
              : "transport";
      }
      return {
        path,
        status,
        reused,
        tcpMs,
        tlsMs,
        tlsResumed,
        headersMs,
        totalMs: performance.now() - started,
        encodedBodyBytes,
        decodedBytes,
        ok,
        reason,
        errorCode,
        runID,
      };
    },
    close() {
      agents["http:"].destroy();
      agents["https:"].destroy();
    },
  };
}

export async function readerOpen(
  connections: ReturnType<typeof readerConnections>,
  origin: URL,
  assets: readonly Asset[],
  lifetime: AbortSignal,
  record: (sample: ReaderTransfer) => void,
  expectedRunID?: string,
) {
  const signal = AbortSignal.any([lifetime, AbortSignal.timeout(6_000)]);
  for (const asset of assets) {
    const result = await connections.transfer(
      origin,
      asset,
      asset.path === "/index.html" ? "/" : asset.path,
      signal,
      expectedRunID,
    );
    record(result);
    if (!result.ok) return { ok: false, reason: result.reason };
  }
  signal.throwIfAborted();
  return { ok: true, reason: "verified" };
}
