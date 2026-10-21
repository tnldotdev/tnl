import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { appendFile, chmod, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import http from "node:http";
import path from "node:path";

// a real child-process boundary with private IPC; no tnl server or cloud calls.
const args = process.argv.slice(2);
const op = args.includes("owner") ? "owner" : args.includes("oidc") ? "oidc" : args[3];
const executable = process.argv[1];
if (!executable) throw new Error("fixture executable missing");
const config = (
  ["status", "stop"].includes(op ?? "") ? {} : JSON.parse(await readFile("fixture.json", "utf8"))
) as {
  capabilities?: "old";
  fail?: boolean;
  noisy?: boolean;
  delay?: number;
  expired?: boolean;
  tooLong?: boolean;
  kube?: boolean;
  secretRuntime?: boolean;
  largeOutput?: boolean;
  invalidJSON?: boolean;
  worktree?: boolean;
  unsafeKubeconfig?: boolean;
  looseHandle?: boolean;
  contextDirectory?: string;
  starterCrash?: "after-response" | "before-response";
  ownerLifetime?: number;
  failStopOnce?: boolean;
  readyAfterSignal?: boolean;
};
const flag = (name: string) => args[args.indexOf(name) + 1] ?? "";
const trace = async (value: object) => appendFile("trace.ndjson", `${JSON.stringify(value)}\n`);
const emit = (value: unknown) => process.stdout.write(JSON.stringify(value));
const runtime = {
  ...(config.worktree
    ? {
        worktree: {
          label: {
            project: "fixture",
            checkout: "review",
            id: "abc",
            fullLabel: "fixture-review-abc",
          },
        },
      }
    : {}),
  namespace: "test.example",
  dev: false,
  services: {
    database: {
      namespace: "test.example",
      hostname: "database.test.example",
      port: 5432,
      public: false,
      protocol: "postgres",
    },
  },
};
await trace({
  op,
  argvHasAssertion: args.some((arg) => arg.includes("fixture-jwt")),
  tracking: process.env.RUNNER_TRACKING_ID,
  oidcBearer: process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN !== undefined,
});
if (op === "oidc") {
  const key = randomBytes(32).toString("hex");
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "", "http://localhost");
    if (
      url.pathname === "/oidc" &&
      req.headers.authorization === "Bearer fixture-bearer" &&
      url.searchParams.get("audience") === "https://control.example"
    ) {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ value: "fixture-jwt-never-log" }));
    } else if (url.pathname === "/stop" && req.headers.authorization === `Bearer ${key}`) {
      res.end("stopped");
      server.close();
    } else res.writeHead(403).end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture listener missing");
  // bound this test-only issuer even if its preparer is interrupted.
  const lifetime = setTimeout(() => server.close(), 60_000);
  lifetime.unref();
  server.once("close", () => clearTimeout(lifetime));
  await writeFile("oidc.json", JSON.stringify({ port: address.port, key }), { mode: 0o600 });
  emit({ url: `http://127.0.0.1:${address.port}/oidc?fixture=1` });
  process.stdout.end();
} else if (op === "capabilities") {
  if (config.largeOutput) process.stderr.write("x".repeat(129 * 1024));
  if (config.invalidJSON) {
    process.stdout.write("fixture-private-json {");
    process.exit(0);
  }
  emit({
    schema: config.capabilities === "old" ? 0 : 1,
    capabilities: ["context", "start", "status", "stop"],
    workload_private: true,
    opaque_private_preflight: true,
    team_names: "applied_binding",
  });
} else if (op === "context") {
  emit({
    schema: 1,
    directory: config.contextDirectory ?? process.cwd(),
    config_digest: "a".repeat(64),
    server: "https://control.example",
    audience: "https://control.example",
    team_id: "tm_fixture",
    project_key: "project-fixture",
    source_id: "source",
    worktree_key: "worktree",
    project_label: "fixture",
    ci: flag("--ci"),
    services: ["database"],
  });
} else if (op === "start") {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
    assertion: string;
    context: { audience: string };
  };
  await trace({
    proofOnStdin: request.assertion === "fixture-jwt-never-log",
    audience: request.context.audience,
  });
  if (config.noisy) {
    process.stderr.write(request.assertion);
    process.exitCode = 1;
  } else if (config.fail) {
    await trace({ partialCleanup: true });
    process.exitCode = 1;
  } else {
    if (config.delay) {
      process.on("SIGTERM", () => {
        void trace({ cancelledCleanup: true }).then(() => process.exit(1));
      });
      await trace({ waitingForSignal: true });
      await new Promise((resolve) => setTimeout(resolve, config.delay));
    }
    const owner = spawn(executable, ["owner", "--runner-temp", flag("--runner-temp")], {
      detached: true,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const output: Buffer[] = [];
    for await (const chunk of owner.stdout) output.push(Buffer.from(chunk));
    if (config.readyAfterSignal) {
      const waiting = new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, 10_000);
        process.once("SIGTERM", () => {
          clearTimeout(timer);
          resolve();
        });
      });
      await trace({ waitingForSignal: true });
      await waiting;
    }
    if (config.starterCrash !== "before-response") {
      await new Promise<void>((resolve, reject) =>
        process.stdout.write(Buffer.concat(output), (error) => (error ? reject(error) : resolve())),
      );
    }
    owner.unref();
    if (config.starterCrash) process.kill(process.pid, "SIGKILL");
  }
} else if (op === "owner") {
  const directory = path.join(flag("--runner-temp"), "tnl-connections-fixture");
  await mkdir(directory, { mode: 0o700 });
  const handle = path.join(directory, "handle.json");
  const kubeconfig = path.join(directory, "kubeconfig");
  const key = randomBytes(32).toString("hex");
  const expires =
    Date.now() +
    (config.ownerLifetime ??
      (config.expired ? -1000 : config.tooLong ? 7 * 60 * 60_000 : 60 * 60_000));
  let ready: object;
  const server = http.createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${key}`) {
      res.writeHead(403).end();
      return;
    }
    if (req.url === "/status") {
      res.end(JSON.stringify(ready));
      return;
    }
    if (req.url === "/stop") {
      void (async () => {
        clearTimeout(lifetime);
        await rm(handle, { force: true });
        await rm(kubeconfig, { force: true });
        await trace({ joinedCleanup: true });
        res.end(JSON.stringify({ schema: 1, state: "stopped" }));
        server.close();
      })();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture listener missing");
  await writeFile(
    handle,
    JSON.stringify({ key, port: address.port, failStopOnce: config.failStopOnce }),
    { mode: 0o600 },
  );
  if (config.looseHandle) await chmod(handle, 0o644);
  if (config.kube) await writeFile(kubeconfig, "fixture private kubeconfig", { mode: 0o600 });
  if (config.unsafeKubeconfig) await symlink("handle.json", kubeconfig);
  // model the native fixed deadline so a test-only lost handoff cannot leave
  // an unbounded detached owner. no PID-based test cleanup is needed.
  const lifetime = setTimeout(
    () => {
      void (async () => {
        await rm(handle, { force: true });
        await rm(kubeconfig, { force: true });
        await trace({ expiredCleanup: true });
        server.close();
      })();
    },
    config.ownerLifetime ?? 60 * 60_000,
  );
  ready = {
    schema: 1,
    state: "ready",
    pid: process.pid,
    expires_at: new Date(expires).toISOString(),
    executable,
    private_handle: handle,
    public_runtime: config.secretRuntime
      ? { ...runtime, private_key: "fixture-private-material" }
      : runtime,
    ...(config.kube || config.unsafeKubeconfig ? { kubeconfig } : {}),
  };
  emit(ready);
  process.stdout.end();
} else if (op === "status" || op === "stop") {
  const handle = flag("--handle");
  const { port, key, failStopOnce } = JSON.parse(await readFile(handle, "utf8")) as {
    port: number;
    key: string;
    failStopOnce?: boolean;
  };
  if (op === "stop" && failStopOnce) {
    await writeFile(handle, JSON.stringify({ port, key }), { mode: 0o600 });
    process.stderr.write("fixture-private-stop-error");
    process.exit(1);
  }
  const response = await fetch(`http://127.0.0.1:${port}/${op}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${key}` },
  });
  process.stdout.write(await response.text());
} else {
  throw new Error("unknown fixture operation");
}
