import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { Agent, request } from "node:http";
import * as path from "node:path";
import { TnlError } from "../errors.js";
import { record, exactKeys } from "./runtime.js";
import { operation, traceHeaders } from "./tracing.js";

export interface OwnerIPC {
  prepare(service: string, assertion?: string): Promise<unknown>;
  close(): void;
}

/** private capability loading mirrors native ownership/symlink/size checks. */
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
    const handle = record(JSON.parse(data.toString("utf8")), "private connection handle");
    exactKeys(
      handle,
      [
        "schema",
        "url",
        "key",
        "directory",
        "config_digest",
        "expires_at",
        "executable",
        ...["workload", "team_id"].filter((k) => Object.hasOwn(handle, k)),
      ],
      "private connection handle",
    );
    if (
      handle.schema !== 1 ||
      typeof handle.url !== "string" ||
      !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}$/.test(handle.url) ||
      typeof handle.key !== "string" ||
      !/^[0-9a-f]{64}$/.test(handle.key) ||
      typeof handle.directory !== "string" ||
      !path.isAbsolute(handle.directory) ||
      typeof handle.config_digest !== "string" ||
      !/^[0-9a-f]{64}$/.test(handle.config_digest) ||
      typeof handle.expires_at !== "string" ||
      !Number.isFinite(Date.parse(handle.expires_at)) ||
      Date.parse(handle.expires_at) <= Date.now()
    )
      throw new Error("invalid handle");
    const endpoint = new URL(handle.url);
    if (Number(endpoint.port) > 65535 || endpoint.origin !== handle.url)
      throw new Error("invalid local origin");
    const key = handle.key;
    const scope = { schema: 1, directory: handle.directory, config_digest: handle.config_digest };
    const expires = Date.parse(handle.expires_at);
    const agent = new Agent({ keepAlive: true, maxSockets: 4, maxFreeSockets: 4 });
    let pending = 0;
    let closed = false;
    return Object.freeze({
      prepare(service: string, assertion?: string): Promise<unknown> {
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
              });
              const req = request(
                new URL("/v1/connections/prepare", endpoint),
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
                      response.statusCode !== 200 ||
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
          } catch {
            throw new TnlError("sdk.connection_unavailable");
          } finally {
            pending--;
          }
        });
      },
      close() {
        closed = true;
        agent.destroy();
      },
    });
  } catch {
    throw new TnlError("sdk.connection_unavailable");
  }
}
