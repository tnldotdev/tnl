import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer, type RequestListener } from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import childProcess from "node:child_process";
import http from "node:http";
import { AsyncLocalStorage } from "node:async_hooks";
import { syncBuiltinESMExports } from "node:module";

// observe real launches and IPC without substituting any SDK/native operation.
const helpers: string[] = [];
const owners: { pid: number; executable: string; alive: boolean }[] = [];
const ipc: string[] = [];
const execFile = childProcess.execFile;
childProcess.execFile = ((...args: Parameters<typeof execFile>) => {
  const argv = args[1];
  if (Array.isArray(argv) && argv[1] === "runtime" && argv[2] === "connections") {
    const operation = String(argv[3]);
    helpers.push(operation);
    const child = execFile(...args);
    if (operation === "start") {
      let data = "";
      child.stdout?.on("data", (chunk: Buffer) => {
        data += chunk.toString();
      });
      child.on("close", (code) => {
        if (code !== 0) return;
        const value: unknown = JSON.parse(data);
        assert(
          value &&
            typeof value === "object" &&
            "pid" in value &&
            typeof value.pid === "number" &&
            "executable" in value &&
            typeof value.executable === "string",
        );
        assert.equal(value.executable, args[0]);
        owners.push({ pid: value.pid, executable: value.executable, alive: true });
      });
    }
    return child;
  }
  throw new Error("unexpected external helper");
}) as typeof execFile;
const execFileSync = childProcess.execFileSync;
childProcess.execFileSync = ((...args: Parameters<typeof execFileSync>) => {
  const argv = args[1];
  assert(Array.isArray(argv) && argv[1] === "runtime" && argv[2] === "connections");
  helpers.push(String(argv[3]));
  return execFileSync(...args);
}) as typeof execFileSync;
const request = http.request;
http.request = ((...args: Parameters<typeof request>) => {
  const url = args[0];
  if (url instanceof URL && url.pathname.startsWith("/v1/connections/")) ipc.push(url.pathname);
  return request(...args);
}) as typeof request;
syncBuiltinESMExports();

// @vercel/oidc reads this documented request context symbol. isolate headers
// per invocation, including concurrent requests; never set a process token.
const context = new AsyncLocalStorage<{ headers: Record<string, string> }>();
Object.defineProperty(globalThis, Symbol.for("@vercel/request-context"), {
  value: { get: () => context.getStore() },
});

// this is only a local Node request/response adapter. the imported entry and all
// of its dependencies must come from the unmodified emitted function directory.
const directory = process.argv[2];
assert(directory && path.isAbsolute(directory));
assert.equal(process.versions.node, "24.20.0");
assert.equal(process.cwd(), directory);
const config: unknown = JSON.parse(await readFile(path.join(directory, ".vc-config.json"), "utf8"));
assert(
  typeof config === "object" &&
    config !== null &&
    "runtime" in config &&
    config.runtime === "nodejs24.x" &&
    "handler" in config &&
    config.handler === "index.mjs",
);
const entry: unknown = await import(pathToFileURL(path.join(directory, config.handler)).href);
assert(
  typeof entry === "object" &&
    entry !== null &&
    "default" in entry &&
    typeof entry.default === "function",
);
const handler = entry.default as RequestListener;
const server = createServer((req, res) => {
  if (req.url === "/__fixture/evidence") {
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        runtime: process.versions.node,
        platform: `${process.platform}-${process.arch}`,
        helpers,
        ipc,
        owners: owners.map((owner) => {
          try {
            process.kill(owner.pid, 0);
            owner.alive = true;
          } catch {
            owner.alive = false;
          }
          assert(owner.executable.startsWith(`${directory}/node_modules/@tnldotdev/tnl-`));
          return owner;
        }),
      }),
    );
    return;
  }
  if (req.url === "/__fixture/shutdown") {
    res.end();
    server.close();
    server.closeAllConnections();
    return;
  }
  const assertion = req.headers["x-vercel-oidc-token"];
  assert(assertion === undefined || typeof assertion === "string");
  context.run(
    { headers: assertion === undefined ? {} : { "x-vercel-oidc-token": assertion } },
    () => handler(req, res),
  );
});
server.listen(0, process.argv[3] === "container" ? "0.0.0.0" : "127.0.0.1", () => {
  const address = server.address();
  assert(address && typeof address !== "string");
  process.stdout.write(`${JSON.stringify({ port: address.port })}\n`);
});
