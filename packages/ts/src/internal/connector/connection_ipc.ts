import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { Agent, request } from "node:http";
import * as path from "node:path";
import { TnlError } from "../../errors.js";
import { connectionHandleSchema } from "./contract.js";
import { operation, traceHeaders } from "../tracing.js";
import { context, type CachedIPC } from "./context.js";
import type { SelectionOptions, WorkloadRequest } from "./workload/contract.js";

export interface OwnerIPC {
  readonly expiresAt: number;
  prepare(service: string, assertion?: string, selection?: SelectionOptions): Promise<unknown>;
  workload(service: string, request: WorkloadRequest): Promise<unknown>;
  close(): void;
}

const { external } = context;
function retire(filename: string, entry: CachedIPC): void {
  if (external.get(filename) === entry) external.delete(filename);
  clearTimeout(entry.timer);
  void entry.loading.then(
    (ipc) => ipc.close(),
    () => {},
  );
}

/** retire idle agents without stopping the caller-owned native process. */
export async function prepareExternal(filename: string, service: string): Promise<unknown> {
  let entry = external.get(filename);
  if (entry === undefined) {
    if (external.size >= 32) {
      const idle = [...external].find(([, candidate]) => candidate.active === 0);
      if (idle === undefined) throw new TnlError("sdk.connection_unavailable");
      retire(...idle);
    }
    entry = { loading: ownerIPC(filename), active: 0 };
    external.set(filename, entry);
  }
  clearTimeout(entry.timer);
  if (entry.failed === true) throw new TnlError("sdk.connection_unavailable");
  entry.active++;
  try {
    const client = await entry.loading;
    entry.expiresAt = client.expiresAt;
    return await client.prepare(service);
  } catch (error) {
    entry.failed = true;
    throw error;
  } finally {
    entry.active--;
    if (entry.active === 0) {
      if (entry.failed === true) retire(filename, entry);
      else {
        const selected = entry;
        entry.timer = setTimeout(
          () => retire(filename, selected),
          Math.min(30_000, (entry.expiresAt ?? Date.now()) - Date.now()),
        );
        entry.timer.unref();
      }
    }
  }
}

/** private capability loading mirrors connector ownership/symlink/size checks. */
export async function ownerIPC(filename: string): Promise<OwnerIPC> {
  try {
    if (
      !path.isAbsolute(filename) ||
      filename.includes("\0") ||
      filename.length > 4096 ||
      process.getuid === undefined
    )
      throw new Error("invalid handle path");
    const parent = path.dirname(filename);
    for (let directory = parent; ; directory = path.dirname(directory)) {
      const info = await lstat(directory);
      if (
        !info.isDirectory() ||
        info.isSymbolicLink() ||
        ((info.mode & 0o022) !== 0 && (info.mode & 0o1000) === 0)
      )
        throw new Error("unsafe handle ancestor");
      if (directory === parent && ((info.mode & 0o777) !== 0o700 || info.uid !== process.getuid()))
        throw new Error("unowned handle directory");
      if (directory === path.dirname(directory)) break;
    }
    const file = await open(
      filename,
      constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW,
    );
    let data: Buffer;
    try {
      const info = await file.stat();
      if (
        !info.isFile() ||
        (info.mode & 0o777) !== 0o600 ||
        info.uid !== process.getuid() ||
        info.size > 128 * 1024
      )
        throw new Error("unowned handle");
      const buffer = Buffer.alloc(128 * 1024 + 1);
      let total = 0;
      while (total < buffer.length) {
        const { bytesRead } = await file.read(buffer, total, buffer.length - total, null);
        if (bytesRead === 0) break;
        total += bytesRead;
      }
      if (total > 128 * 1024) throw new Error("oversized handle");
      data = buffer.subarray(0, total);
    } finally {
      await file.close();
    }
    const handle = connectionHandleSchema.parse(JSON.parse(data.toString("utf8")));
    const endpoint = new URL(handle.url);
    const key = handle.key;
    const scope = { schema: 1, directory: handle.directory, config_digest: handle.config_digest };
    const expires = handle.expires_at;
    const agent = new Agent({ keepAlive: true, maxSockets: 4, maxFreeSockets: 4 });
    let pending = 0;
    let closed = false;
    const close = () => {
      closed = true;
      clearTimeout(expiry);
      agent.destroy();
    };
    const expiry = setTimeout(close, Math.min(expires - Date.now(), 2 ** 31 - 1));
    expiry.unref();
    const send = (
      operationName: "prepare" | "sdk-prepare" | "sdk-workload",
      service: string,
      assertion?: string,
      selection?: SelectionOptions,
    ): Promise<unknown> => {
      return operation("sdk.native.request", async () => {
        if (closed || pending >= 64 || Date.now() >= expires)
          throw new TnlError("sdk.connection_unavailable");
        pending++;
        try {
          return await new Promise<unknown>((resolve, reject) => {
            const body = JSON.stringify({
              ...scope,
              service,
              ...(assertion === undefined ? {} : { assertion }),
              ...selection,
            });
            const req = request(
              new URL(`/v1/connections/${operationName}`, endpoint),
              {
                method: "POST",
                agent,
                headers: {
                  ...traceHeaders(),
                  authorization: `Bearer ${key}`,
                  "content-type": "application/json",
                  "content-length": Buffer.byteLength(body),
                },
              },
              (response) => {
                const chunks: Buffer[] = [];
                let size = 0;
                response.on("data", (chunk: Buffer) => {
                  size += chunk.length;
                  if (size > 128 * 1024) {
                    response.destroy();
                    reject(new TnlError("sdk.response_invalid"));
                  } else chunks.push(chunk);
                });
                response.on("error", () => reject(new TnlError("sdk.connection_unavailable")));
                response.on("end", () => {
                  if (
                    (response.statusCode !== 200 && operationName === "prepare") ||
                    response.headers["content-type"]?.split(";")[0] !== "application/json"
                  ) {
                    reject(new TnlError("sdk.connection_unavailable"));
                    return;
                  }
                  try {
                    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
                    resolve(value);
                  } catch {
                    reject(new TnlError("sdk.response_invalid"));
                  }
                });
              },
            );
            const timer = setTimeout(() => req.destroy(new Error("owner IPC deadline")), 35_000);
            req.once("close", () => clearTimeout(timer));
            req.once("error", () => reject(new TnlError("sdk.connection_unavailable")));
            req.end(body);
          });
        } catch (cause) {
          throw cause instanceof TnlError ? cause : new TnlError("sdk.connection_unavailable");
        } finally {
          pending--;
        }
      });
    };
    return Object.freeze({
      expiresAt: expires,
      prepare: (service: string, assertion?: string, selection?: SelectionOptions) =>
        send(selection === undefined ? "prepare" : "sdk-prepare", service, assertion, selection),
      workload: (service: string, request: WorkloadRequest) =>
        send("sdk-workload", service, undefined, { sdk_workload: request }),
      close,
    });
  } catch {
    throw new TnlError("sdk.connection_unavailable");
  }
}
