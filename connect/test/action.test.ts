import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import http from "node:http";
import path from "node:path";
import { promisify } from "node:util";
import { build } from "esbuild";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { main, post } from "../src/action.js";
import { nativeJSON } from "../src/native.js";
import { installedBinary, selectBinary } from "../src/resolve.js";
import { ActionError, safeActionMessage, type ActionErrorCode } from "../src/errors.js";

const run = promisify(execFile);
let root: string;
let project: string;
let temp: string;
let binary: string;
let state: string;
let envFile: string;
let output: string[];

beforeEach(async () => {
  root = await realpath(await mkdtemp(path.join(tmpdir(), "tnl-action-test-")));
  project = path.join(root, "checkout");
  temp = path.join(root, "runner temp\nline");
  await mkdir(project);
  await mkdir(temp);
  binary = path.join(root, "tnl");
  await build({
    entryPoints: [new URL("./native-fixture.ts", import.meta.url).pathname],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    outfile: binary,
    banner: { js: `#!${process.execPath}` },
  });
  await chmod(binary, 0o700);
  await writeFile(path.join(project, "fixture.json"), "{}");
  state = path.join(root, "state");
  envFile = path.join(root, "env");
  await writeFile(state, "");
  await writeFile(envFile, "");
  vi.stubEnv("GITHUB_WORKSPACE", project);
  vi.stubEnv("RUNNER_TEMP", temp);
  vi.stubEnv("GITHUB_STATE", state);
  vi.stubEnv("GITHUB_ENV", envFile);
  vi.stubEnv("INPUT_WORKLOAD", "deploy");
  vi.stubEnv("INPUT_CLI-PATH", binary);
  vi.stubEnv("INPUT_TIMEOUT", "5");
  vi.stubEnv("INPUT_VERSION", "");
  vi.stubEnv("INPUT_SERVICES", "database");
  vi.stubEnv("INPUT_WORKING-DIRECTORY", ".");
  vi.stubEnv("RUNNER_TRACKING_ID", "runner-fixture-tracking");
  vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "fixture-bearer");
  vi.stubEnv("TNL_CONNECTION_HANDLE", "");
  vi.stubEnv("TNL_PROJECT_RUNTIME", "");
  vi.stubEnv("KUBECONFIG", "");
  output = [];
  vi.spyOn(process.stdout, "write").mockImplementation((chunk) => {
    output.push(String(chunk));
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((chunk) => {
    output.push(String(chunk));
    return true;
  });
});

// parse the actual Actions multiline file protocol, including paths with LF.
function fileCommands(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const split = line.indexOf("<<");
    if (split < 0) continue;
    const name = line.slice(0, split);
    const end = line.slice(split + 2);
    const value = [];
    while (++i < lines.length && lines[i] !== end) value.push(lines[i]);
    result[name] = value.join("\n");
  }
  return result;
}

async function saved() {
  const fields = fileCommands(await readFile(state, "utf8"));
  const data = fields["tnl-cleanup"];
  if (!data) throw new Error("missing action state");
  return JSON.parse(data) as { session: string; binary: string; handle?: string };
}

afterEach(async () => {
  // cleanup through the action, even on a failed assertion; never kill by PID.
  let owned: Awaited<ReturnType<typeof saved>> | undefined;
  try {
    owned = await saved();
  } catch {
    /* this test did not run main */
  }
  try {
    if (owned !== undefined) {
      vi.stubEnv("STATE_tnl-cleanup", JSON.stringify(owned));
      try {
        await post();
      } catch (error) {
        // a failed start without a delivered capability cannot prove joined
        // cleanup. the short-lived crash fixture checks native expiry itself.
        if (!(error instanceof ActionError && error.code === "TNL_ACTION_CLEANUP_UNCONFIRMED"))
          throw error;
      }
    }
  } finally {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    await rm(root, { recursive: true, force: true });
  }
});

const oidc = async (audience: string) => {
  expect(audience).toBe("https://control.example");
  const traces = await readFile(path.join(project, "trace.ndjson"), "utf8");
  expect(traces).toContain('"op":"capabilities"');
  expect(traces).toContain('"op":"context"');
  return "fixture-jwt-never-log";
};

async function actionFailure(
  operation: Promise<unknown>,
  code: ActionErrorCode,
): Promise<ActionError> {
  try {
    await operation;
  } catch (error) {
    expect(error).toBeInstanceOf(ActionError);
    if (!(error instanceof ActionError)) throw error;
    expect(error.code).toBe(code);
    return error;
  }
  throw new Error("expected an action failure");
}

function entrypoint(env: NodeJS.ProcessEnv = {}, entry = "main") {
  const url = new URL(`../dist/${entry}/index.mjs`, import.meta.url).href;
  // the hosted entrypoint supports Linux only; exercise that actual bundle on
  // the maintainer's macOS host too. native fixtures still use this host's Node.
  const script = `Object.defineProperty(process, "platform", {value: "linux"}); await import(${JSON.stringify(url)});`;
  return new Promise<{ code: string | number | null | undefined; stdout: string; stderr: string }>(
    (resolve) => {
      execFile(
        process.execPath,
        ["--input-type=module", "--eval", script],
        {
          env: { ...process.env, ...env },
        },
        (error, stdout, stderr) => resolve({ code: error?.code, stdout, stderr }),
      );
    },
  );
}

describe("native main and post", () => {
  test("OIDC acquisition has a deadline even when the provider never settles", async () => {
    vi.stubEnv("INPUT_TIMEOUT", "1");
    await actionFailure(
      main({ signal: new AbortController().signal, getIDToken: () => new Promise(() => {}) }),
      "TNL_ACTION_OIDC_FAILED",
    );
    expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).not.toContain(
      '"op":"start"',
    );
    const owned = await saved();
    await expect(stat(owned.session)).rejects.toMatchObject({ code: "ENOENT" });
  });
  test("cancellation interrupts a pending OIDC provider and never starts native connections", async () => {
    const controller = new AbortController();
    let entered: (() => void) | undefined;
    const ready = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let finish: ((token: string) => void) | undefined;
    const running = main({
      signal: controller.signal,
      getIDToken: () => {
        entered?.();
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    }).catch((error: unknown) => error);
    await ready;
    controller.abort();
    const result = await Promise.race([
      running,
      new Promise((resolve) => setTimeout(() => resolve("waiting"), 100)),
    ]);
    finish?.("late.private.assertion");
    await running;
    expect(result).toMatchObject({ code: "TNL_ACTION_CANCELLED" });
    expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).not.toContain(
      '"op":"start"',
    );
    expect(output.join("")).not.toContain("late.private.assertion");
  });
  test("ready owner survives steps; exact copied binary and private handle clean up after checkout changes", async () => {
    await writeFile(
      path.join(project, "fixture.json"),
      JSON.stringify({ kube: true, worktree: true }),
    );
    await main({ signal: new AbortController().signal, getIDToken: oidc });
    const owned = await saved();
    const fields = fileCommands(await readFile(envFile, "utf8"));
    expect(fields.TNL_CONNECTION_HANDLE).toBe(owned.handle);
    expect(fields.KUBECONFIG).toContain(temp);
    expect(JSON.parse(fields.TNL_PROJECT_RUNTIME ?? "")).toMatchObject({
      services: { database: { port: 5432 } },
      worktree: {
        label: {
          project: "fixture",
          checkout: "review",
          id: "abc",
          fullLabel: "fixture-review-abc",
        },
      },
    });
    expect(owned.binary).not.toBe(binary);
    expect((await stat(owned.session)).mode & 0o777).toBe(0o700);
    expect((await stat(owned.handle ?? "")).mode & 0o777).toBe(0o600);
    // a separate native invocation models an ordinary later workflow step.
    expect(
      await nativeJSON(owned.binary, ["status", "--handle", owned.handle ?? ""], {
        cwd: project,
        timeout: 5000,
      }),
    ).toMatchObject({ state: "ready" });
    await rm(binary);
    await rm(path.join(project, "node_modules"), { recursive: true, force: true });
    const childPost = await run(
      process.execPath,
      [new URL("../dist/post/index.mjs", import.meta.url).pathname],
      {
        cwd: path.resolve("."),
        env: { ...process.env, "STATE_tnl-cleanup": JSON.stringify(owned), PATH: "/unusable/path" },
      },
    );
    expect(childPost.stdout).toContain("tnl connections stopped");
    await expect(readFile(owned.session)).rejects.toThrow();
    const traces = await readFile(path.join(project, "trace.ndjson"), "utf8");
    expect(traces).toContain('"proofOnStdin":true');
    expect(traces).toContain('"joinedCleanup":true');
    expect(traces).not.toContain('"argvHasAssertion":true');
    expect(traces).not.toContain('"oidcBearer":true');
    expect(traces).toContain('"tracking":"runner-fixture-tracking"');
    expect(output.join("")).not.toContain("fixture-jwt");
    expect(await readFile(state, "utf8")).not.toContain("fixture-jwt");
    expect(await readFile(envFile, "utf8")).not.toContain("fixture-jwt");
  });

  test.each([{ expired: true }, { tooLong: true }])(
    "rejects an invalid fixed deadline and joins owned cleanup: %j",
    async (config) => {
      await writeFile(path.join(project, "fixture.json"), JSON.stringify(config));
      await expect(
        main({ signal: new AbortController().signal, getIDToken: oidc }),
      ).rejects.toThrow("valid ready");
      expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
        '"joinedCleanup":true',
      );
      expect(await readFile(envFile, "utf8")).toBe("");
    },
  );

  test("rejects private material added to public runtime before environment exports", async () => {
    await writeFile(path.join(project, "fixture.json"), JSON.stringify({ secretRuntime: true }));
    await expect(main({ signal: new AbortController().signal, getIDToken: oidc })).rejects.toThrow(
      "valid ready",
    );
    expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
      '"joinedCleanup":true',
    );
    expect(await readFile(envFile, "utf8")).toBe("");
    expect(output.join("")).not.toContain("fixture-private-material");
  });

  test("bounds native output and fails before OIDC", async () => {
    await writeFile(path.join(project, "fixture.json"), JSON.stringify({ largeOutput: true }));
    const getIDToken = vi.fn(oidc);
    await actionFailure(
      main({ signal: new AbortController().signal, getIDToken }),
      "TNL_ACTION_RESPONSE_TOO_LARGE",
    );
    expect(getIDToken).not.toHaveBeenCalled();
  });

  test("workload is required before any OIDC or native startup", async () => {
    vi.stubEnv("INPUT_WORKLOAD", "");
    const getIDToken = vi.fn(oidc);
    await expect(main({ signal: new AbortController().signal, getIDToken })).rejects.toThrow(
      "workload",
    );
    expect(getIDToken).not.toHaveBeenCalled();
    await expect(readFile(path.join(project, "trace.ndjson"))).rejects.toThrow();
  });

  test("old capabilities fail before requesting OIDC, without a fallback", async () => {
    await writeFile(path.join(project, "fixture.json"), JSON.stringify({ capabilities: "old" }));
    const getIDToken = vi.fn(oidc);
    await expect(main({ signal: new AbortController().signal, getIDToken })).rejects.toThrow(
      "capabilities",
    );
    expect(getIDToken).not.toHaveBeenCalled();
    expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).not.toContain(
      '"op":"start"',
    );
  });

  test("official OIDC client requests the context audience and masks proof before native stdin", async () => {
    const server = http.createServer((req, res) => {
      expect(new URL(req.url ?? "", "http://localhost").searchParams.get("audience")).toBe(
        "https://control.example",
      );
      expect(req.headers.authorization).toBe("Bearer fixture-bearer");
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ value: "fixture-jwt-never-log" }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("fixture listener missing");
      vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_URL", `http://127.0.0.1:${address.port}/oidc?fixture=1`);
      vi.stubEnv("NO_PROXY", "127.0.0.1");
      await main({ signal: new AbortController().signal });
      const rendered = output.filter((line) => !line.startsWith("::add-mask::"));
      expect(rendered.join("")).not.toContain("fixture-jwt");
      expect(await readFile(envFile, "utf8")).not.toContain("fixture-jwt");
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });

  test("offline workflow fixture carries ready connections across separate steps and bundled post", async () => {
    const workflow = new URL("./workflow.ts", import.meta.url).pathname;
    const outputs = path.join(root, "outputs");
    await writeFile(outputs, "");
    await run(process.execPath, [workflow, "prepare"], {
      env: { ...process.env, GITHUB_OUTPUT: outputs },
    });
    const fields = fileCommands(await readFile(outputs, "utf8"));
    vi.stubEnv("INPUT_CLI-PATH", fields.binary);
    vi.stubEnv("INPUT_WORKING-DIRECTORY", fields.project);
    vi.stubEnv("ACTIONS_ID_TOKEN_REQUEST_URL", fields.oidc);
    vi.stubEnv("NO_PROXY", "127.0.0.1");
    const env = { ...process.env, FIXTURE_ROOT: fields.root };
    try {
      await main({ signal: new AbortController().signal });
      await run(process.execPath, [workflow, "observe"]);
      await run(process.execPath, [workflow, "remove-original"], { env });
      await run(process.execPath, [workflow, "observe"]);
      await run(process.execPath, [new URL("../dist/post/index.mjs", import.meta.url).pathname], {
        env: {
          ...process.env,
          "STATE_tnl-cleanup": JSON.stringify(await saved()),
          PATH: "/unusable/path",
        },
      });
      const rendered = output.filter((line) => !line.startsWith("::add-mask::"));
      expect(rendered.join("")).not.toContain("fixture-jwt");
      expect(await readFile(path.join(fields.project ?? "", "trace.ndjson"), "utf8")).toContain(
        '"joinedCleanup":true',
      );
    } finally {
      await run(process.execPath, [workflow, "stop-oidc"], { env });
    }
  });

  test("environment-file failure after readiness cleans only this action's owner", async () => {
    await main({ signal: new AbortController().signal, getIDToken: oidc });
    const first = await saved();
    vi.stubEnv("GITHUB_ENV", path.join(root, "missing/file"));
    await expect(
      main({ signal: new AbortController().signal, getIDToken: oidc }),
    ).rejects.toThrow();
    expect(
      await nativeJSON(first.binary, ["status", "--handle", first.handle ?? ""], {
        cwd: project,
        timeout: 5000,
      }),
    ).toMatchObject({ state: "ready" });
    vi.stubEnv("STATE_tnl-cleanup", JSON.stringify(first));
    await post();
  });

  test("setup and cleanup causes both survive; post retries the exact saved handle", async () => {
    await writeFile(path.join(project, "fixture.json"), JSON.stringify({ failStopOnce: true }));
    vi.stubEnv("GITHUB_ENV", path.join(root, "fixture-private-env/missing"));
    const error = await actionFailure(
      main({ signal: new AbortController().signal, getIDToken: oidc }),
      "TNL_ACTION_EXPORT_FAILED",
    );
    expect(error.cause).toBeInstanceOf(AggregateError);
    if (error.cause instanceof AggregateError) {
      expect(error.cause.errors).toMatchObject([
        {
          code: "TNL_ACTION_EXPORT_FAILED",
          cause: { message: expect.stringContaining("fixture-private-env") },
        },
        { code: "TNL_ACTION_COMMAND_FAILED", cause: { code: 1 } },
      ]);
    }
    expect(safeActionMessage(error, "TNL_ACTION_SETUP_FAILED") + output.join("")).not.toContain(
      "fixture-private",
    );
    vi.stubEnv("STATE_tnl-cleanup", JSON.stringify(await saved()));
    await post();
    expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
      '"joinedCleanup":true',
    );
  });

  test.each([{ fail: true }, { noisy: true }])(
    "partial startup failure cannot log a JWT: %j",
    async (config) => {
      await writeFile(path.join(project, "fixture.json"), JSON.stringify(config));
      await expect(
        main({ signal: new AbortController().signal, getIDToken: oidc }),
      ).rejects.toThrow("native command failed");
      expect(output.join("")).not.toContain("fixture-jwt");
      expect(await readFile(envFile, "utf8")).toBe("");
    },
  );

  test("startup timeout lets the native command clean partial helpers", async () => {
    await writeFile(path.join(project, "fixture.json"), JSON.stringify({ delay: 10_000 }));
    vi.stubEnv("INPUT_TIMEOUT", "1");
    await actionFailure(
      main({ signal: new AbortController().signal, getIDToken: oidc }),
      "TNL_ACTION_COMMAND_TIMEOUT",
    );
    expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
      '"cancelledCleanup":true',
    );
  });

  test("cancellation lets the native command clean partial helpers", async () => {
    await writeFile(path.join(project, "fixture.json"), JSON.stringify({ delay: 10_000 }));
    const controller = new AbortController();
    const reason = new Error("fixture-private-abort-reason");
    const failed = actionFailure(
      main({ signal: controller.signal, getIDToken: oidc }),
      "TNL_ACTION_CANCELLED",
    );
    try {
      await vi.waitFor(
        async () =>
          expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
            '"waitingForSignal":true',
          ),
        { timeout: 10_000 },
      );
      controller.abort(reason);
      const error = await failed;
      expect(error.cause).toBeInstanceOf(AggregateError);
      if (error.cause instanceof AggregateError) expect(error.cause.errors[0].cause).toBe(reason);
      expect(safeActionMessage(error, "TNL_ACTION_SETUP_FAILED")).not.toContain("fixture-private");
    } finally {
      controller.abort(reason);
      await failed.catch(() => {});
    }
    expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
      '"cancelledCleanup":true',
    );
  });

  test("a starter killed after delivering readiness still yields exact joined cleanup", async () => {
    await writeFile(
      path.join(project, "fixture.json"),
      JSON.stringify({ starterCrash: "after-response" }),
    );
    const error = await actionFailure(
      main({ signal: new AbortController().signal, getIDToken: oidc }),
      "TNL_ACTION_COMMAND_FAILED",
    );
    expect(error.cause).toEqual({ code: null, signal: "SIGKILL" });
    expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
      '"joinedCleanup":true',
    );
    expect(await readFile(envFile, "utf8")).toBe("");
    await expect(stat((await saved()).session)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test.each(["timeout", "cancel"])(
    "a clean starter exit cannot erase a raced %s, and its delivered handle is stopped",
    async (kind) => {
      await writeFile(
        path.join(project, "fixture.json"),
        JSON.stringify({ readyAfterSignal: true }),
      );
      const controller = new AbortController();
      vi.stubEnv("INPUT_TIMEOUT", kind === "timeout" ? "3" : "15");
      const failed = actionFailure(
        main({ signal: controller.signal, getIDToken: oidc }),
        kind === "timeout" ? "TNL_ACTION_COMMAND_TIMEOUT" : "TNL_ACTION_CANCELLED",
      );
      try {
        if (kind === "cancel") {
          await vi.waitFor(
            async () =>
              expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
                '"waitingForSignal":true',
              ),
            { timeout: 10_000 },
          );
          controller.abort("fixture-private-reason");
        }
        await failed;
        expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
          '"joinedCleanup":true',
        );
        expect(await readFile(envFile, "utf8")).toBe("");
        expect(output.join("")).not.toContain("fixture-private-reason");
      } finally {
        controller.abort("fixture-private-reason");
        await failed.catch(() => {});
      }
    },
  );

  test("a lost response retains native files and relies on the fixed deadline without a handle or PID kill", async () => {
    await writeFile(
      path.join(project, "fixture.json"),
      JSON.stringify({ starterCrash: "before-response", ownerLifetime: 500 }),
    );
    await actionFailure(
      main({ signal: new AbortController().signal, getIDToken: oidc }),
      "TNL_ACTION_COMMAND_FAILED",
    );
    const owned = await saved();
    expect(owned.handle).toBeUndefined();
    expect((await stat(owned.session)).isDirectory()).toBe(true);
    vi.stubEnv("STATE_tnl-cleanup", JSON.stringify(owned));
    await actionFailure(post(), "TNL_ACTION_CLEANUP_UNCONFIRMED");
    await vi.waitFor(async () => {
      expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
        '"expiredCleanup":true',
      );
    });
    expect(await readFile(envFile, "utf8")).toBe("");
  });

  test.each([{ unsafeKubeconfig: true }, { looseHandle: true }])(
    "rejects actual unsafe private files before exporting readiness: %j",
    async (config) => {
      await writeFile(path.join(project, "fixture.json"), JSON.stringify(config));
      const error = await actionFailure(
        main({ signal: new AbortController().signal, getIDToken: oidc }),
        "TNL_ACTION_READY_INVALID",
      );
      expect(error.cause).toMatchObject({ code: "TNL_ACTION_CLEANUP_PATH_INVALID" });
      expect(await readFile(envFile, "utf8")).toBe("");
      expect(await readFile(path.join(project, "trace.ndjson"), "utf8")).toContain(
        '"joinedCleanup":true',
      );
    },
  );
});

describe("safe failure boundaries", () => {
  test("filesystem failures preserve the OS cause and the shipped entrypoint never renders its path", async () => {
    const missing = path.join(root, "fixture-private-path");
    vi.stubEnv("INPUT_WORKING-DIRECTORY", missing);
    const error = await actionFailure(
      main({ signal: new AbortController().signal }),
      "TNL_ACTION_DIRECTORY_INVALID",
    );
    expect(error.cause).toMatchObject({ code: "ENOENT", path: missing });
    const result = await entrypoint();
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("TNL_ACTION_DIRECTORY_INVALID");
    expect(result.stdout + result.stderr).not.toContain("fixture-private-path");
  });

  test("binary copy failures preserve the filesystem cause without rendering it", async () => {
    vi.stubEnv("INPUT_CLI-PATH", path.join(root, "fixture-private-binary"));
    const error = await actionFailure(
      main({ signal: new AbortController().signal }),
      "TNL_ACTION_BINARY_COPY_FAILED",
    );
    expect(error.cause).toMatchObject({ code: "ENOENT" });
    const result = await entrypoint();
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("TNL_ACTION_BINARY_COPY_FAILED");
    expect(result.stdout + result.stderr).not.toContain("fixture-private-binary");
  });

  test("only the owned type selects displayed text, including unexpected abort reasons", async () => {
    const cause = new Error("fixture-private-provider-text");
    cause.name = "ActionError";
    Object.assign(cause, { code: "TNL_ACTION_CANCELLED" });
    expect(safeActionMessage(cause, "TNL_ACTION_SETUP_FAILED")).toBe(
      "[TNL_ACTION_SETUP_FAILED] tnl action setup failed",
    );
    const controller = new AbortController();
    controller.abort(cause);
    const error = await actionFailure(main({ signal: controller.signal }), "TNL_ACTION_CANCELLED");
    expect(error.cause).toBe(cause);
    error.message = "fixture-private-replaced-message";
    expect(safeActionMessage(error, "TNL_ACTION_SETUP_FAILED")).toBe(
      "[TNL_ACTION_CANCELLED] tnl connection startup was cancelled",
    );
    expect(output.join("")).not.toContain("fixture-private");
  });

  test("OIDC rejection retains its original cause and uses authored auth guidance", async () => {
    const cause = new Error("fixture-private-oidc-body");
    const error = await actionFailure(
      main({
        signal: new AbortController().signal,
        getIDToken: async () => {
          throw cause;
        },
      }),
      "TNL_ACTION_OIDC_FAILED",
    );
    expect(error.cause).toBe(cause);
    expect(safeActionMessage(error, "TNL_ACTION_SETUP_FAILED")).toContain("id-token: write");
    expect(output.join("")).not.toContain(cause.message);
  });

  test("official OIDC rejection cannot leak a provider response through the shipped entrypoint", async () => {
    const server = http.createServer((_req, res) => {
      res.writeHead(403, { "content-type": "application/json" });
      res.end(JSON.stringify({ message: "fixture-private-oidc-response" }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("fixture listener missing");
      const result = await entrypoint({
        ACTIONS_ID_TOKEN_REQUEST_URL: `http://127.0.0.1:${address.port}/oidc?fixture=1`,
        NO_PROXY: "127.0.0.1",
      });
      expect(result.code).toBe(1);
      expect(result.stdout).toContain("TNL_ACTION_OIDC_FAILED");
      expect(result.stdout + result.stderr).not.toContain("fixture-private-oidc-response");
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });

  test("spawn and JSON decoding failures keep causes behind owned codes", async () => {
    const missing = path.join(root, "fixture-private-executable");
    const spawnError = await actionFailure(
      nativeJSON(missing, ["capabilities"], { cwd: project, timeout: 1000 }),
      "TNL_ACTION_EXEC_FAILED",
    );
    expect(spawnError.cause).toMatchObject({ code: "ENOENT", path: missing });
    await writeFile(path.join(project, "fixture.json"), JSON.stringify({ invalidJSON: true }));
    const jsonError = await actionFailure(
      main({ signal: new AbortController().signal }),
      "TNL_ACTION_JSON_INVALID",
    );
    expect(jsonError.cause).toBeInstanceOf(SyntaxError);
    const result = await entrypoint();
    expect(result.stdout).toContain("TNL_ACTION_JSON_INVALID");
    expect(result.stdout + result.stderr).not.toContain("fixture-private-json");
  });

  test("the request byte bound rejects before spawning a child", async () => {
    await actionFailure(
      nativeJSON(binary, ["start"], {
        cwd: project,
        timeout: 1000,
        input: "x".repeat(128 * 1024 + 1),
      }),
      "TNL_ACTION_REQUEST_TOO_LARGE",
    );
    await expect(readFile(path.join(project, "trace.ndjson"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  test("canonical context directory is checked before OIDC", async () => {
    const alias = path.join(root, "alias");
    await symlink(project, alias);
    await writeFile(
      path.join(project, "fixture.json"),
      JSON.stringify({ contextDirectory: alias }),
    );
    const getIDToken = vi.fn(oidc);
    await actionFailure(
      main({ signal: new AbortController().signal, getIDToken }),
      "TNL_ACTION_CONTEXT_INVALID",
    );
    expect(getIDToken).not.toHaveBeenCalled();
  });

  test("post renders fixed text for malformed saved state without dumping its contents", async () => {
    const result = await entrypoint({ "STATE_tnl-cleanup": '{"fixture-private-state":' }, "post");
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("TNL_ACTION_STATE_INVALID");
    expect(result.stdout + result.stderr).not.toContain("fixture-private-state");
  });
});

async function installFixture(version = "1.2.3") {
  const store = path.join(project, "node_modules/.pnpm/tnl-test/node_modules");
  const launcher = path.join(store, "@tnldotdev/tnl");
  const nativeName = `@tnldotdev/tnl-${process.platform}-${process.arch}`;
  const platform = path.join(store, nativeName);
  await mkdir(path.join(launcher, "dist"), { recursive: true });
  await mkdir(path.join(platform, "bin"), { recursive: true });
  const native = await readFile(binary);
  await writeFile(
    path.join(launcher, "package.json"),
    JSON.stringify({
      name: "@tnldotdev/tnl",
      version,
      exports: { ".": "./dist/index.js" },
      optionalDependencies: { [nativeName]: version },
    }),
  );
  await writeFile(
    path.join(launcher, "dist/index.js"),
    'throw new Error("must not import the SDK")',
  );
  await writeFile(
    path.join(platform, "package.json"),
    JSON.stringify({
      name: nativeName,
      version,
      tnl: { binarySha256: createHash("sha256").update(native).digest("hex") },
    }),
  );
  await writeFile(path.join(platform, "bin/tnl"), native, { mode: 0o700 });
  for (const file of ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"])
    await writeFile(path.join(platform, file), `fixture ${file}`);
  await mkdir(path.join(project, "node_modules/@tnldotdev"), { recursive: true });
  await symlink(launcher, path.join(project, "node_modules/@tnldotdev/tnl"));
  return platform;
}

async function npmFixture() {
  const npm = path.join(temp, "npm");
  await build({
    entryPoints: [new URL("./npm-fixture.ts", import.meta.url).pathname],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    outfile: npm,
    banner: { js: `#!${process.execPath}\nprocess.argv.splice(2, 0, ${JSON.stringify(project)});` },
  });
  await chmod(npm, 0o700);
  vi.stubEnv("PATH", temp);
  vi.stubEnv("INPUT_CLI-PATH", "");
}

describe("installed exact package resolution", () => {
  test("explicit exact version installs in runner temp with scripts disabled and retains legal files", async () => {
    await installFixture("1.2.3-rc.4");
    await npmFixture();
    vi.stubEnv("INPUT_VERSION", "1.2.3-rc.4");
    await main({ signal: new AbortController().signal, getIDToken: oidc });
    const args = JSON.parse(
      await readFile(path.join(project, "npm-args.json"), "utf8"),
    ) as string[];
    expect(args).toContain("@tnldotdev/tnl@1.2.3-rc.4");
    expect(args).toContain("--ignore-scripts");
    expect(args).toContain("--include=optional");
    expect(args).not.toContain("latest");
    const owned = await saved();
    expect(args[args.indexOf("--prefix") + 1]).toBe(path.join(owned.session, "install"));
    expect(
      await readFile(path.join(path.dirname(owned.binary), "THIRD_PARTY_LICENSES.txt"), "utf8"),
    ).toBe("fixture THIRD_PARTY_LICENSES.txt");
  });

  test("npm failures retain classified causes without printing either child stream", async () => {
    await npmFixture();
    vi.stubEnv("INPUT_VERSION", "1.2.3");
    await writeFile(path.join(project, "fixture.json"), JSON.stringify({ npmFail: true }));
    const error = await actionFailure(
      main({ signal: new AbortController().signal }),
      "TNL_ACTION_INSTALL_FAILED",
    );
    expect(error.cause).toMatchObject({
      code: "TNL_ACTION_COMMAND_FAILED",
      cause: { code: 1, signal: null },
    });
    const result = await entrypoint();
    expect(result.code).toBe(1);
    expect(result.stdout).toContain("TNL_ACTION_INSTALL_FAILED");
    expect(result.stdout + result.stderr + output.join("")).not.toContain("fixture-private-npm");
  });

  test("an installed package missing legal files fails before OIDC", async () => {
    const platform = await installFixture();
    await rm(path.join(platform, "NOTICE"));
    vi.stubEnv("INPUT_CLI-PATH", "");
    const getIDToken = vi.fn(oidc);
    const error = await actionFailure(
      main({ signal: new AbortController().signal, getIDToken }),
      "TNL_ACTION_LEGAL_FILES_MISSING",
    );
    expect(error.cause).toMatchObject({ code: "ENOENT", path: path.join(platform, "NOTICE") });
    expect(getIDToken).not.toHaveBeenCalled();
    await expect(readFile(path.join(project, "trace.ndjson"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  test("pnpm monorepo discovers the launcher despite private package.json exports", async () => {
    const platform = await installFixture();
    const nested = path.join(project, "apps/web");
    await mkdir(nested, { recursive: true });
    expect(await installedBinary(nested)).toBe(path.join(platform, "bin/tnl"));
    vi.stubEnv("INPUT_CLI-PATH", "");
    await main({ signal: new AbortController().signal, getIDToken: oidc });
    const owned = await saved();
    expect(await readFile(path.join(path.dirname(owned.binary), "LICENSE"), "utf8")).toBe(
      "fixture LICENSE",
    );
  });

  test("missing installed package does not use PATH or install latest", async () => {
    vi.stubEnv("INPUT_CLI-PATH", "");
    const getIDToken = vi.fn(oidc);
    await expect(main({ signal: new AbortController().signal, getIDToken })).rejects.toThrow(
      "installed exact",
    );
    expect(getIDToken).not.toHaveBeenCalled();
    await expect(readFile(path.join(project, "trace.ndjson"))).rejects.toThrow();
  });

  test.each(["missing", "version", "optional", "digest", "mode"])(
    "broken exact platform fails without fallback: %s",
    async (kind) => {
      const platform = await installFixture();
      if (kind === "missing") await rm(path.join(platform, "bin/tnl"));
      if (kind === "version") {
        const file = path.join(platform, "package.json");
        const manifest = JSON.parse(await readFile(file, "utf8")) as Record<string, unknown>;
        await writeFile(file, JSON.stringify({ ...manifest, version: "1.2.4" }));
      }
      if (kind === "optional") {
        const file = path.join(project, "node_modules/@tnldotdev/tnl/package.json");
        const manifest = JSON.parse(await readFile(file, "utf8")) as Record<string, unknown>;
        await writeFile(
          file,
          JSON.stringify({
            ...manifest,
            optionalDependencies: {
              [`@tnldotdev/tnl-${process.platform}-${process.arch}`]: "^1.2.3",
            },
          }),
        );
      }
      if (kind === "digest") await writeFile(path.join(platform, "bin/tnl"), "broken binary");
      if (kind === "mode") await chmod(path.join(platform, "bin/tnl"), 0o600);
      await actionFailure(installedBinary(project), "TNL_ACTION_BINARY_UNAVAILABLE");
    },
  );

  test.each(["latest", "v1.2.3", "^1.2.3", "1.2", "1.2.3-01", "https://example.test/tnl.tgz"])(
    "rejects an inexact version before installing: %s",
    async (version) => {
      await expect(
        selectBinary({
          directory: project,
          session: temp,
          version,
          cliPath: "",
          signal: new AbortController().signal,
        }),
      ).rejects.toThrow("exact release");
    },
  );
});
