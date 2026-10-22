import { execFile } from "node:child_process";
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { createServer } from "node:net";
import * as z from "zod";
import { afterEach, beforeEach, expect, onTestFinished, test, vi } from "vitest";
import {
  connectionFixtureEvent,
  connectionFixturePlan,
} from "./test-helper/connection-owner-fixture.js";

const native = vi.hoisted(() => ({ resolve: vi.fn<() => string>() }));
vi.mock("./src/internal/launcher.js", () => ({ resolveNativeBinary: native.resolve }));
const run = promisify(execFile);
let root: string;
let binary: string;
let plan: z.infer<typeof connectionFixturePlan>;
const events = async () =>
  (
    await readFile(path.join(root, "events.ndjson"), "utf8").catch((error: unknown) => {
      if (error instanceof Error && "code" in error && error.code === "ENOENT") return "";
      throw error;
    })
  )
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => connectionFixtureEvent.parse(JSON.parse(line) as unknown));
async function configure(change: Partial<z.infer<typeof connectionFixturePlan>>): Promise<void> {
  plan = { ...plan, ...change };
  await writeFile(path.join(root, "plan.json"), JSON.stringify(plan));
}
async function owner(): Promise<{ file: string; pid: number }> {
  const started = (await events()).findLast((event) => event.event === "ready");
  if (started?.file === undefined) throw new Error("fixture owner did not start");
  return { file: started.file, pid: started.pid };
}
async function control(file: string, operation: string): Promise<Response> {
  const handle = z
    .object({ url: z.string().url(), key: z.string() })
    .parse(JSON.parse(await readFile(file, "utf8")) as unknown);
  return fetch(`${handle.url}${operation}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${handle.key}` },
    signal: AbortSignal.timeout(20_000),
  });
}
async function holdCredential(file: string): Promise<() => Promise<void>> {
  const before = (await events()).filter((event) => event.event === "blocked").length;
  const pending = control(file, "/v1/connections/kube-credential").then((response) =>
    response.arrayBuffer(),
  );
  // arm rejection before a failed test's cleanup releases or closes the request.
  void pending.catch(() => {});
  await expect
    .poll(async () => (await events()).filter((event) => event.event === "blocked").length, {
      timeout: 10_000,
    })
    .toBe(before + 1);
  return async () => {
    await (await control(file, "/fixture/release")).arrayBuffer();
    await pending;
  };
}

async function waitForDeadline(file: string): Promise<void> {
  const descriptor = z
    .object({ expires_at: z.string().datetime() })
    .parse(JSON.parse(await readFile(file, "utf8")) as unknown);
  await delay(Math.max(0, Date.parse(descriptor.expires_at) - Date.now() + 50));
}

async function assertPortFree(port: number): Promise<void> {
  const listener = createServer();
  await new Promise<void>((resolve, reject) => {
    listener.once("error", reject);
    listener.listen(port, "127.0.0.1", resolve);
  });
  await new Promise<void>((resolve, reject) =>
    listener.close((error) => (error ? reject(error) : resolve())),
  );
}

beforeEach(async () => {
  vi.resetModules();
  vi.stubEnv("TNL_CONNECTION_HANDLE", undefined);
  for (const name of ["TNL_WORKLOAD", "GITHUB_ACTIONS", "VERCEL", "FLY_APP_NAME"])
    vi.stubEnv(name, undefined);
  root = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-owner-recovery-")));
  binary = path.join(root, "tnl.mts");
  const fixture = pathToFileURL(
    path.resolve(import.meta.dirname, "test-helper/connection-owner-fixture.ts"),
  ).href;
  await writeFile(
    binary,
    `#!/usr/bin/env node\nimport {runConnectionOwnerFixture} from ${JSON.stringify(fixture)};\nawait runConnectionOwnerFixture(${JSON.stringify(root)});\n`,
  );
  await chmod(binary, 0o755);
  native.resolve.mockReturnValue(binary);
  plan = connectionFixturePlan.parse({});
  await configure({});
  const exitListeners = new Set(process.listeners("beforeExit"));
  onTestFinished(async () => {
    await configure({ stop: "ready" });
    for (const event of await events()) {
      if (event.event !== "ready" || event.file === undefined) continue;
      try {
        for (const operation of ["/fixture/release", "/fixture/release-stop"])
          await (await control(event.file, operation)).arrayBuffer();
        await run(
          binary,
          ["--no-telemetry", "runtime", "connections", "stop", "--handle", event.file],
          { timeout: 5000 },
        );
      } catch (error) {
        if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) {
          try {
            process.kill(event.pid, "SIGTERM");
          } catch {
            /* already joined */
          }
          throw error;
        }
      }
    }
    for (const listener of process.listeners("beforeExit"))
      if (!exitListeners.has(listener)) process.removeListener("beforeExit", listener);
    await rm(root, { recursive: true, force: true });
  });
});
afterEach(() => vi.unstubAllEnvs());

test("a timed-out prepared read retains the live owner and its fixed-port listener", async () => {
  const { connectionHandle } = await import("./src/internal/connection.js");
  const handle = connectionHandle("database", vi.fn());
  const first = await handle;
  const original = await owner();
  const release = await holdCredential(original.file);
  await expect(Promise.resolve(handle)).rejects.toMatchObject({
    code: "sdk.connection_unavailable",
  });
  expect(() => process.kill(original.pid, 0)).not.toThrow();
  expect((await events()).filter((event) => event.event === "start")).toHaveLength(1);
  expect((await events()).filter((event) => event.event === "stop")).toHaveLength(0);
  await release();
  expect(await connectionHandle("database", vi.fn())).toEqual(first);
  expect({ ...handle }).toEqual(first);
  expect((await events()).filter((event) => event.event === "ready")).toHaveLength(1);
  expect(await owner()).toEqual(original);
}, 20_000);

test("canceling HTTP preparation leaves the shared owner and other awaiters intact", async () => {
  await configure({ protocol: "http" });
  const { connectionHandle } = await import("./src/internal/connection.js");
  const handle = connectionHandle("database", vi.fn());
  const settings = await handle;
  if (!("fetch" in settings)) throw new Error("expected HTTP settings");
  const original = await owner();
  const release = await holdCredential(original.file);
  const abort = new AbortController();
  const canceled = settings.fetch("/", { signal: abort.signal });
  const reason = new DOMException("the caller stopped waiting", "AbortError");
  const rejected = expect(canceled).rejects.toBe(reason);
  const waiting = Promise.resolve(connectionHandle("database", vi.fn()));
  await expect
    .poll(async () => (await events()).filter((event) => event.event === "read").length, {
      timeout: 10_000,
    })
    .toBe(2);
  abort.abort(reason);
  await rejected;
  expect((await events()).filter((event) => event.event === "read-canceled")).toHaveLength(0);
  await release();
  expect(await waiting).toMatchObject({ url: settings.url });
  expect({ ...handle }).toMatchObject({ url: settings.url });
  expect((await events()).filter((event) => event.event === "start")).toHaveLength(1);
  expect((await events()).filter((event) => event.event === "stop")).toHaveLength(0);
  expect(await owner()).toEqual(original);
}, 20_000);

test("failed initial validation joins cleanup before any same-port replacement", async () => {
  await configure({ prepared: "invalid", stop: "hold" });
  const { connectionHandle } = await import("./src/internal/connection.js");
  const handle = connectionHandle("database", vi.fn());
  const first = expect(Promise.resolve(handle)).rejects.toMatchObject({
    code: "sdk.response_invalid",
  });
  await expect
    .poll(async () => (await events()).filter((event) => event.event === "stop").length, {
      // separate command and owner processes can take longer than Vitest's
      // one-second default on a shared runner. retain the native command bound.
      timeout: 10_000,
    })
    .toBe(1);
  const original = await owner();
  const port = await readFile(path.join(root, "port"), "utf8");
  const second = expect(
    Promise.resolve(connectionHandle("database", vi.fn())),
  ).rejects.toMatchObject({ code: "sdk.response_invalid" });
  expect(() => ({ ...handle })).toThrow(
    expect.objectContaining({ code: "sdk.connection_unprepared" }),
  );
  expect((await events()).filter((event) => event.event === "start")).toHaveLength(1);
  await (await control(original.file, "/fixture/release-stop")).arrayBuffer();
  await Promise.all([first, second]);
  await configure({ prepared: "ready", stop: "ready" });
  const recovered = await handle;
  expect(recovered).toHaveProperty("server", `https://127.0.0.1:${port}`);
  expect({ ...handle }).toEqual(recovered);
  const history = await events();
  expect(history.filter((event) => event.event === "start")).toHaveLength(2);
  expect(history.findIndex((event) => event.event === "closed")).toBeLessThan(
    history.findLastIndex((event) => event.event === "start"),
  );
  expect((await owner()).pid).not.toBe(original.pid);
}, 20_000);

test("an initial service read timeout retains the new shared owner for later preparation", async () => {
  await configure({ prepared: "blocked" });
  const { connectionHandle } = await import("./src/internal/connection.js");
  const handle = connectionHandle("database", vi.fn());
  await expect(Promise.resolve(handle)).rejects.toMatchObject({
    code: "sdk.connection_unavailable",
  });
  const original = await owner();
  expect((await events()).filter((event) => event.event === "closed")).toHaveLength(0);
  await (await control(original.file, "/fixture/release")).arrayBuffer();
  await configure({ prepared: "ready" });
  const settings = await handle;
  expect({ ...handle }).toEqual(settings);
  expect((await owner()).pid).toBe(original.pid);
  expect((await events()).filter((event) => event.event === "start")).toHaveLength(1);
}, 20_000);

test("concurrent awaits after a known deadline join and replace one same-port owner", async () => {
  await configure({ lifetimeMs: 4000, cleanupDelayMs: 500 });
  const { connectionHandle } = await import("./src/internal/connection.js");
  const handle = connectionHandle("database", vi.fn());
  const first = await handle;
  const frozenFirst = JSON.stringify(first);
  const original = await owner();
  const port = Number(await readFile(path.join(root, "port"), "utf8"));
  await waitForDeadline(original.file);
  const before = (await events()).filter((event) =>
    ["start", "read", "stop"].includes(event.event),
  );
  expect(() => ({ ...handle })).toThrow(
    expect.objectContaining({ code: "sdk.connection_unprepared" }),
  );
  expect(
    (await events()).filter((event) => ["start", "read", "stop"].includes(event.event)),
  ).toEqual(before);
  const current = await Promise.all(
    Array.from({ length: 8 }, () => Promise.resolve(connectionHandle("database", vi.fn()))),
  );
  expect(current.every((settings) => Object.isFrozen(settings))).toBe(true);
  expect(current[0]).toMatchObject({ server: `https://127.0.0.1:${port}` });
  expect(current.every((settings) => JSON.stringify(settings) === JSON.stringify(current[0]))).toBe(
    true,
  );
  expect(Object.isFrozen(first)).toBe(true);
  expect(JSON.stringify(first)).toBe(frozenFirst);
  expect(current[0]).not.toEqual(first);
  expect({ ...handle }).toEqual(current[0]);
  const replacement = await owner();
  expect(replacement.pid).not.toBe(original.pid);
  const history = await events();
  expect(history.filter((event) => event.event === "start")).toHaveLength(2);
  expect(history.findIndex((event) => event.event === "closed")).toBeLessThan(
    history.findLastIndex((event) => event.event === "start"),
  );
  await run(binary, [
    "--no-telemetry",
    "runtime",
    "connections",
    "stop",
    "--handle",
    replacement.file,
  ]);
  await assertPortFree(port);
}, 20_000);

test("expired caller-owned handles fail without SDK replacement or cleanup", async () => {
  await configure({ lifetimeMs: 4000 });
  const { stdout } = await run(binary, ["--no-telemetry", "runtime", "connections", "start"]);
  const external = z.object({ private_handle: z.string() }).parse(JSON.parse(stdout) as unknown);
  vi.stubEnv("TNL_CONNECTION_HANDLE", external.private_handle);
  const { connectionHandle } = await import("./src/internal/connection.js");
  const handle = connectionHandle("database", vi.fn());
  await handle;
  await waitForDeadline(external.private_handle);
  await expect(Promise.resolve(handle)).rejects.toMatchObject({
    code: "sdk.connection_unavailable",
  });
  expect(() => ({ ...handle })).toThrow();
  expect((await events()).filter((event) => event.event === "start")).toHaveLength(1);
  expect((await events()).filter((event) => event.event === "stop")).toHaveLength(0);
}, 20_000);

test("expiry recovery reports current authentication denial instead of reusing old rights", async () => {
  await configure({ lifetimeMs: 4000 });
  const { connectionHandle } = await import("./src/internal/connection.js");
  const handle = connectionHandle("database", vi.fn());
  await handle;
  const original = await owner();
  const port = Number(await readFile(path.join(root, "port"), "utf8"));
  await configure({ authorization: "deny" });
  await waitForDeadline(original.file);
  await expect(Promise.all([handle, connectionHandle("database", vi.fn())])).rejects.toMatchObject({
    code: "sdk.authentication_required",
  });
  const history = await events();
  expect(history.filter((event) => event.event === "start")).toHaveLength(2);
  expect(history.filter((event) => event.event === "ready")).toHaveLength(1);
  expect(history.filter((event) => event.event === "closed")).toHaveLength(1);
  expect(() => ({ ...handle })).toThrow(
    expect.objectContaining({ code: "sdk.connection_unprepared" }),
  );
  await assertPortFree(port);
}, 20_000);
