import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { createServer as createTCPServer } from "node:net";
import { appendFile, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import * as z from "zod";

export const connectionFixturePlan = z.object({
  protocol: z.enum(["kubernetes", "http"]).default("kubernetes"),
  prepared: z.enum(["ready", "invalid", "blocked"]).default("ready"),
  stop: z.enum(["ready", "hold"]).default("ready"),
  lifetimeMs: z.number().int().min(500).max(60_000).default(60_000),
  cleanupDelayMs: z.number().int().min(0).max(5000).default(0),
  authorization: z.enum(["allow", "deny"]).default("allow"),
});
export const connectionFixtureEvent = z.object({
  event: z.enum(["start", "ready", "stop", "closed", "blocked", "read", "read-canceled"]),
  pid: z.number().int().positive(),
  file: z.string().optional(),
});
const fixtureHandle = z.object({ url: z.string().url(), key: z.string() });

/** separate command/owner processes exercise real socket ownership and joining. */
export async function runConnectionOwnerFixture(root: string): Promise<void> {
  const args = process.argv.slice(2);
  const event = async (event: z.infer<typeof connectionFixtureEvent>["event"], file?: string) => {
    await appendFile(
      path.join(root, "events.ndjson"),
      `${JSON.stringify({ event, pid: process.pid, ...(file === undefined ? {} : { file }) })}\n`,
    );
  };
  const plan = async () =>
    connectionFixturePlan.parse(
      JSON.parse(await readFile(path.join(root, "plan.json"), "utf8")) as unknown,
    );
  try {
    if (args[0] === "--fixture-owner") {
      const protocol = (await plan()).protocol;
      const portFile = path.join(root, "port");
      const port = await readFile(portFile, "utf8")
        .then(Number)
        .catch((error: unknown) => {
          if (error instanceof Error && "code" in error && error.code === "ENOENT") return 0;
          throw error;
        });
      const listener = createTCPServer((socket) => socket.end());
      await new Promise<void>((resolve, reject) => {
        listener.once("error", reject);
        listener.listen(port, "127.0.0.1", resolve);
      });
      const address = listener.address();
      if (address === null || typeof address === "string") throw new Error("missing fixture port");
      await writeFile(portFile, String(address.port));
      const directory = path.join(root, `owner-${process.pid}`);
      const file = path.join(directory, "handle.json");
      await mkdir(directory, { mode: 0o700 });
      const key = randomBytes(32).toString("hex");
      let release: (() => void) | undefined;
      let held: Promise<void> | undefined;
      let finishStop: (() => void) | undefined;
      let stopGate: Promise<void> | undefined;
      let stopping: Promise<void> | undefined;
      if ((await plan()).prepared === "blocked")
        held = new Promise<void>((resolve) => {
          release = resolve;
        });
      const lifetimeMs = (await plan()).lifetimeMs;
      const expires_at = new Date(Date.now() + lifetimeMs).toISOString();
      const url = "https://database.team.example:15443";
      const project = {
        dev: false,
        namespace: "team.example",
        services: {
          database: {
            protocol,
            hostname: "database.team.example",
            namespace: "team.example",
            public: true,
            port: 15443,
            url,
          },
        },
      };
      const snapshot = {
        schema: 1,
        project_runtime: project,
        connection: {
          schema: 1,
          protocol,
          host: "127.0.0.1",
          port: address.port,
          url,
          expires_at,
          ssl: { servername: "database.team.example", rejectUnauthorized: true },
          ...(protocol === "kubernetes"
            ? { kubeconfig: path.join(directory, "kubeconfig"), context: "tnl:database" }
            : {}),
        },
      };
      const owner = createServer((request, response) => {
        void (async () => {
          if (request.headers.authorization !== `Bearer ${key}`) {
            response.writeHead(401).end();
            return;
          }
          const operation = request.url;
          if (operation === "/fixture/release") {
            release?.();
            held = undefined;
          } else if (operation === "/fixture/release-stop") {
            finishStop?.();
          } else if (operation === "/v1/connections/kube-credential") {
            held = new Promise<void>((resolve) => {
              release = resolve;
            });
            await event("blocked");
            await held;
          } else if (
            operation === "/v1/connections/prepared" ||
            operation === "/v1/connections/prepare"
          ) {
            await event("read");
            response.once("close", () => {
              if (!response.writableEnded) void event("read-canceled").catch(() => {});
            });
            let timer: ReturnType<typeof setTimeout> | undefined;
            if (held !== undefined) timer = setTimeout(() => response.destroy(), 5000);
            try {
              await held;
            } finally {
              if (timer !== undefined) clearTimeout(timer);
            }
            if (response.destroyed) return;
            response.setHeader("Content-Type", "application/json");
            response.end(
              JSON.stringify(
                (await plan()).prepared === "invalid" ? { ...snapshot, schema: 2 } : snapshot,
              ),
            );
            return;
          } else if (operation === "/v1/connections/stop") {
            const setting = (await plan()).stop;
            if (stopping === undefined) {
              if (setting === "hold")
                stopGate = new Promise<void>((resolve) => {
                  finishStop = resolve;
                });
              const flushed = new Promise<void>((resolve) => response.once("finish", resolve));
              stopping = (async () => {
                await flushed;
                await stopGate;
                await close();
              })();
            }
            await event("stop");
          }
          response.setHeader("Content-Type", "application/json");
          response.end(JSON.stringify({ schema: 1, state: "stopping" }));
        })().catch(() => response.destroy());
      });
      const close = async () => {
        release?.();
        await delay((await plan()).cleanupDelayMs);
        const closed = new Promise<void>((resolve) => owner.close(() => resolve()));
        owner.closeAllConnections();
        await Promise.all([
          closed,
          new Promise<void>((resolve) => listener.close(() => resolve())),
        ]);
        await unlink(file);
        await event("closed");
        await writeFile(path.join(directory, "closed"), "joined");
      };
      const shutdown = () => {
        finishStop?.();
        if (stopping === undefined) stopping = close();
      };
      process.once("SIGTERM", shutdown);
      setTimeout(shutdown, Math.max(1, Date.parse(expires_at) - Date.now())).unref();
      await new Promise<void>((resolve) => owner.listen(0, "127.0.0.1", resolve));
      const control = owner.address();
      if (control === null || typeof control === "string") throw new Error("missing fixture owner");
      await writeFile(
        file,
        JSON.stringify({
          schema: 1,
          url: `http://127.0.0.1:${control.port}`,
          key,
          expires_at,
          directory: root,
          config_digest: "c".repeat(64),
          executable: process.argv[1],
        }),
        {
          mode: 0o600,
        },
      );
      await event("ready", file);
      process.stdout.end(
        JSON.stringify({
          schema: 1,
          state: "ready",
          pid: process.pid,
          expires_at,
          project_runtime: project,
          connection_handle: file,
          executable: process.argv[1],
        }),
      );
      return;
    }
    const operation = args[3];
    if (operation === "start") {
      await event("start");
      if ((await plan()).authorization === "deny") {
        process.stderr.write(JSON.stringify({ reason: "TNL_CLIENT_AUTHENTICATION_REQUIRED" }));
        process.exitCode = 1;
        return;
      }
      const entry = process.argv[1];
      if (entry === undefined) throw new Error("missing fixture entry");
      const child = spawn(process.execPath, [entry, "--fixture-owner"], {
        detached: true,
        stdio: ["ignore", "pipe", "ignore"],
      });
      const chunks: Buffer[] = [];
      for await (const chunk of child.stdout) {
        if (!Buffer.isBuffer(chunk)) throw new Error("invalid fixture output");
        chunks.push(chunk);
      }
      child.unref();
      const data = Buffer.concat(chunks);
      if (data.length === 0) throw new Error("owner startup failed");
      process.stdout.write(data);
      return;
    }
    const file = args[args.indexOf("--handle") + 1];
    if (file === undefined) throw new Error("missing fixture handle");
    if (operation === "stop") {
      try {
        await readFile(path.join(path.dirname(file), "closed"));
      } catch {
        const descriptor = await readFile(file, "utf8").catch((error: unknown) => {
          if (error instanceof Error && "code" in error && error.code === "ENOENT")
            return undefined;
          throw error;
        });
        if (descriptor !== undefined) {
          const handle = fixtureHandle.parse(JSON.parse(descriptor) as unknown);
          const response = await fetch(`${handle.url}/v1/connections/stop`, {
            method: "POST",
            headers: { Authorization: `Bearer ${handle.key}` },
            signal: AbortSignal.timeout(5000),
          });
          if (!response.ok) throw new Error("fixture stop failed");
          await response.arrayBuffer();
        }
        for (;;) {
          try {
            await readFile(path.join(path.dirname(file), "closed"));
            break;
          } catch {
            await delay(10);
          }
        }
      }
      process.stdout.write(JSON.stringify({ schema: 1, state: "stopped" }));
      return;
    }
    if (operation !== "read") throw new Error("invalid fixture command");
    const handle = fixtureHandle.parse(JSON.parse(await readFile(file, "utf8")) as unknown);
    const response = await fetch(`${handle.url}/v1/connections/prepared`, {
      method: "POST",
      headers: { Authorization: `Bearer ${handle.key}` },
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error("fixture read failed");
    process.stdout.write(await response.text());
  } catch {
    process.stderr.write(JSON.stringify({ reason: "TNL_CLIENT_CONNECTION_UNAVAILABLE" }));
    process.exitCode = 1;
  }
}
