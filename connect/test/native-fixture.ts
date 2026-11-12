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
  starterCrash?: "after-response" | "before-response";
  ownerLifetime?: number;
  failStopOnce?: boolean;
  readyAfterSignal?: boolean;
  providerDelay?: boolean;
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
const selection = {
  environment: { server: "https://control.example", project_key: "project-fixture", environment_id: `env_${"e".repeat(22)}` },
  permission_id: `mwp_${"p".repeat(22)}`,
  services: { database: "postgres" },
};
await trace({
  op,
  directory: process.cwd(),
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
    capabilities: ["environment-start", "status", "stop"],
    environment_visitors: true,
  });
} else if (op === "environment-start") {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
    selection: typeof selection;
    source: { kind: string; machine_id: string };
    acquisition: { method: string; audience: string };
    github_actions_refresh?: {
      audience: string;
      request_url: string;
      request_token: string;
    };
  };
  await trace({
    explicitSourceOnStdin: request.source.kind === "oidc" && request.source.machine_id === `mci_${"m".repeat(22)}` && request.selection.permission_id === selection.permission_id && request.acquisition.method === "github-actions",
    audience: request.acquisition.audience,
    actionRefreshOnStdin:
      request.github_actions_refresh?.audience === request.acquisition.audience &&
      request.github_actions_refresh.request_url ===
        "https://runtime.example.test/token?keep=yes&audience=wrong" &&
      request.github_actions_refresh.request_token === "fixture-bearer",
    argvHasRuntimeCredential: args.some((arg) => arg.includes("fixture-bearer")),
  });
  await trace({ providerSourceRead: true });
  if (config.providerDelay) {
    process.once("SIGTERM", () => { void trace({ providerCanceled: true }).then(() => process.exit(1)); });
    await new Promise(() => {});
  }
  const source = request.github_actions_refresh;
  if (source?.request_url.startsWith("http://127.0.0.1:")) {
    // the synthetic native executable uses a loopback test issuer. production
    // native separately enforces HTTPS, no redirects, bounds and execution trust.
    const url = new URL(source.request_url);
    url.searchParams.set("audience", request.acquisition.audience);
    const response = await fetch(url, { headers: { authorization: `Bearer ${source.request_token}` }, redirect: "error" });
    if (!response.ok) {
      process.stderr.write(await response.text());
      process.exit(1);
    }
    const value: unknown = await response.json();
    if (value === null || typeof value !== "object" || !("value" in value) || typeof value.value !== "string") throw new Error("invalid test provider reply");
  }
  if (config.noisy) {
    process.stderr.write(request.github_actions_refresh?.request_token ?? "private-runtime-bearer");
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
    connection_handle: handle,
    project_runtime: config.secretRuntime
      ? { ...runtime, private_key: "fixture-private-material" }
      : runtime,
    environment: { environment: selection.environment, applied_definition_revision: 1, mutation_revision: 1, services: { database: { service_id: `svc_${"s".repeat(22)}`, protocol: "postgres", endpoint: { hostname: "database.test.example", port: 5432, public: false } } } },
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
