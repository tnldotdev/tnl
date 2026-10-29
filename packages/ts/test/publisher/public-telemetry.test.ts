import { createServer } from "node:http";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, onTestFinished, test, vi } from "vitest";
import * as z from "zod";
import { tnl, TnlError } from "@tnldotdev/tnl";
import { withTnl } from "@tnldotdev/tnl/next";
import viteTnl from "@tnldotdev/tnl/vite";
import { testPublicProject } from "../helpers/project.js";
import { withProcessEnvironment } from "../helpers/environment.js";

const native = vi.hoisted(() => ({ binary: "", launches: 0 }));
// only replace native executable discovery; public entries, normalization, startup,
// endpoint validation, and http ipc run their real implementations.
vi.mock("../../dist/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => {
    native.launches++;
    return native.binary;
  },
}));

afterEach(async () => {
  for (const preparation of globalThis.__tnlAppPreparations?.values() ?? [])
    await preparation.then(
      (handle) => handle.close(),
      () => {},
    );
});

test.each([
  ["true", "false", true],
  ["false", "true", false],
] as const)(
  "public prepare captures %s before lazy import and retains it on recovery",
  async (initial, later, disabled) => {
    const fixture = await publicRuntime();
    await withProcessEnvironment(
      { ...fixture.environment, TNL_NO_TELEMETRY: initial },
      async () => {
        const pending = tnl.prepare();
        process.env.TNL_NO_TELEMETRY = later;
        const handle = await pending;
        const app = await listener();
        try {
          fixture.faults.register = true;
          await handle.register(app);
          expect(
            fixture.requests.filter((request) => request.path === "/v1/prepare"),
          ).toMatchObject([
            { body: { telemetry_disabled: disabled } },
            { body: { telemetry_disabled: disabled } },
          ]);
        } finally {
          await handle.close();
        }
      },
    );
  },
);

test("public prepare uses captured normalized choices for cache identity", async () => {
  const fixture = await publicRuntime();
  await withProcessEnvironment({ ...fixture.environment, TNL_NO_TELEMETRY: "1" }, async () => {
    const first = tnl.prepare();
    process.env.TNL_NO_TELEMETRY = "true";
    const equivalent = tnl.prepare();
    process.env.TNL_NO_TELEMETRY = "false";
    const different = tnl.prepare();
    process.env.TNL_NO_TELEMETRY = "TRUE";
    const [one, same, other] = await Promise.all([first, equivalent, different]);
    expect(same).toBe(one);
    expect(other).not.toBe(one);
    expect(one.publicURL).toBe("https://disabled.member.example");
    expect(other.publicURL).toBe("https://enabled.member.example");
    const preparations = fixture.requests.filter((request) => request.path === "/v1/prepare");
    expect(preparations).toHaveLength(2);
    expect(preparations.map((request) => request.body.telemetry_disabled)).toEqual(
      expect.arrayContaining([true, false]),
    );
  });
});

test.each([
  ["listener", "true", "false", true],
  ["listener", "false", "true", false],
  ["fetch", "true", "false", true],
  ["fetch", "false", "true", false],
] as const)(
  "public %s open captures %s before lazy import and retains it on recovery",
  async (form, initial, later, disabled) => {
    const fixture = await publicRuntime();
    const app = await listener();
    await withProcessEnvironment({ TNL_NO_TELEMETRY: initial }, async () => {
      fixture.faults.status = true;
      const pending = tnl.open(form === "listener" ? app : () => new Response("app"));
      process.env.TNL_NO_TELEMETRY = later;
      const handle = await pending;
      try {
        expect(
          fixture.requests.filter((request) => request.path === "/v1/ad-hoc/register"),
        ).toMatchObject([
          { body: { telemetry_disabled: disabled } },
          { body: { telemetry_disabled: disabled } },
        ]);
        expect(native.launches).toBe(2);
      } finally {
        await handle.close();
      }
    });
  },
);

test.each(["prepare", "listener", "fetch"] as const)(
  "public %s rejects initial invalid input as a Promise before native startup",
  async (entry) => {
    const fixture = await publicRuntime();
    const app = await listener();
    await withProcessEnvironment({ TNL_NO_TELEMETRY: "private-invalid-setting" }, async () => {
      const pending =
        entry === "prepare"
          ? tnl.prepare()
          : tnl.open(entry === "listener" ? app : () => new Response("app"));
      process.env.TNL_NO_TELEMETRY = "false";
      expect(pending).toBeInstanceOf(Promise);
      const result = await pending.then(
        async (handle) => {
          await handle.close();
          return undefined;
        },
        (error: unknown) => error,
      );
      expect(result).toBeInstanceOf(TnlError);
      expect(result).toMatchObject({
        code: "sdk.configuration_invalid",
        message: new TnlError("sdk.configuration_invalid").message,
      });
      expect(native.launches).toBe(0);
      expect(fixture.healthRequests()).toBe(0);
      expect(fixture.requests).toEqual([]);
    });
  },
);

test("public Next config captures before awaiting user configuration", async () => {
  const fixture = await publicRuntime();
  await withProcessEnvironment(
    {
      ...fixture.environment,
      TNL_NO_TELEMETRY: "yes",
      __NEXT_PRIVATE_ORIGIN: "http://127.0.0.1:3200",
    },
    async () => {
      const configure = withTnl(async () => {
        await Promise.resolve();
        return {};
      });
      const pending = configure("phase-development-server", { defaultConfig: {} });
      process.env.TNL_NO_TELEMETRY = "false";
      await pending;
      expect(fixture.requests[0]?.body).toMatchObject({
        framework: "next",
        telemetry_disabled: true,
      });
    },
  );
});

test("public Next config rejects invalid telemetry before invoking user configuration", async () => {
  const fixture = await publicRuntime();
  await withProcessEnvironment(
    { ...fixture.environment, TNL_NO_TELEMETRY: "private-invalid-setting" },
    async () => {
      const config = vi.fn(async () => ({}));
      const pending = withTnl(config)("phase-development-server", { defaultConfig: {} });
      process.env.TNL_NO_TELEMETRY = "false";
      await expect(pending).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
      expect(config).not.toHaveBeenCalled();
      expect(fixture.requests).toEqual([]);
      expect(native.launches).toBe(0);
    },
  );
});

test("public Vite config captures at its development hook entry", async () => {
  const fixture = await publicRuntime();
  await withProcessEnvironment({ ...fixture.environment, TNL_NO_TELEMETRY: "TRUE" }, async () => {
    const hook = viteTnl().config;
    if (typeof hook !== "function") throw new Error("missing config hook");
    const pending = hook.call(
      {} as never,
      {},
      { command: "serve", isPreview: false, mode: "development" },
    );
    process.env.TNL_NO_TELEMETRY = "false";
    await pending;
    expect(fixture.requests[0]?.body).toMatchObject({
      framework: "vite",
      telemetry_disabled: true,
    });
  });
});

test("public framework hooks are inert during builds, including invalid telemetry settings", async () => {
  const fixture = await publicRuntime();
  await withProcessEnvironment(
    { ...fixture.environment, TNL_NO_TELEMETRY: "private-invalid-setting" },
    async () => {
      await expect(withTnl({})("phase-production-build", { defaultConfig: {} })).resolves.toEqual(
        {},
      );
      const hook = viteTnl().config;
      if (typeof hook !== "function") throw new Error("missing config hook");
      await expect(
        hook.call({} as never, {}, { command: "build", isPreview: false, mode: "production" }),
      ).resolves.toBeUndefined();
      expect(fixture.requests).toEqual([]);
    },
  );
});

async function listener() {
  const app = createServer((_request, response) => response.end("app"));
  await new Promise<void>((resolve) => app.listen(0, "127.0.0.1", resolve));
  onTestFinished(() => new Promise<void>((resolve) => app.close(() => resolve())));
  return app;
}

async function publicRuntime() {
  const directory = await mkdtemp(join(tmpdir(), "tnl-public-telemetry-"));
  const requests: { path: string | undefined; body: Record<string, unknown> }[] = [];
  const faults = { register: false, status: false };
  let health = 0;
  let invocation: { invocation_id: string; owner: string; target: string } | undefined;
  const registration = `reg_${"a".repeat(32)}`;
  const api = createServer((request, response) => {
    if (request.url === "/v1/health") {
      health++;
      response.writeHead(204).end();
      return;
    }
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const raw = Buffer.concat(chunks).toString();
      const body = z.record(z.string(), z.unknown()).parse(raw === "" ? {} : JSON.parse(raw));
      requests.push({ path: request.url, body });
      response.setHeader("Content-Type", "application/json");
      if (
        (request.url === "/v1/register" && faults.register) ||
        (request.url === "/v1/status" && faults.status)
      ) {
        faults.register = faults.status = false;
        response.writeHead(409).end(
          JSON.stringify({
            code: "runtime.registration_stale",
            message: "fixture owner restarted",
          }),
        );
      } else if (request.url === "/v1/prepare") {
        // correlate each handle with its validated request, not concurrent arrival order.
        const { telemetry_disabled: disabled } = z
          .object({ telemetry_disabled: z.boolean() })
          .parse(body);
        const hostname = `${disabled ? "disabled" : "enabled"}.member.example`;
        const publicURL = `https://${hostname}`;
        const project = testPublicProject(true);
        project.services.api = { ...project.services.api, hostname, url: publicURL };
        response.end(
          JSON.stringify({
            version: 1,
            registration_id: registration,
            service: "api",
            hostname,
            public_url: publicURL,
            project,
          }),
        );
      } else if (request.url === "/v1/ad-hoc/register") {
        invocation = z
          .looseObject({ invocation_id: z.string(), owner: z.string(), target: z.string() })
          .parse(body);
        response.end(
          JSON.stringify({
            version: 1,
            registration_id: registration,
            owner: invocation.owner,
            target: invocation.target,
          }),
        );
      } else if (request.url === "/v1/status" && invocation !== undefined) {
        response.end(
          JSON.stringify({
            schema_version: 1,
            project: directory,
            cursor: "cursor",
            observed_at: new Date().toISOString(),
            services: [
              {
                service: invocation.invocation_id,
                directory: ".",
                registration_id: registration,
                target: invocation.target,
                registered: true,
                routable: true,
                ready: false,
                readiness: { path: "/" },
                public_url: "https://temporary.member.example",
                publish_run_number: 1,
              },
            ],
          }),
        );
      } else response.writeHead(204).end();
    });
  });
  await new Promise<void>((resolve) => api.listen(0, "127.0.0.1", resolve));
  onTestFinished(async () => {
    await new Promise<void>((resolve) => api.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  });
  const address = api.address();
  if (address === null || typeof address === "string") throw new Error("missing listener");
  const endpoint = {
    version: 1,
    url: `http://127.0.0.1:${address.port}`,
    capability: "a".repeat(64),
    owner_id: "b".repeat(32),
  };
  const descriptor = join(directory, "endpoint.json");
  await writeFile(descriptor, JSON.stringify({ ...endpoint, scope: "app", service: "api" }), {
    mode: 0o400,
  });
  native.binary = join(directory, "endpoint.mjs");
  native.launches = 0;
  await writeFile(
    native.binary,
    `#!${process.execPath}\nconst id = process.argv[process.argv.indexOf("--invocation-id") + 1];\nif (!/^ivk_[A-Za-z0-9]{22}$/.test(id ?? "")) process.exit(1);\nprocess.stdout.write(JSON.stringify({...${JSON.stringify(endpoint)}, scope: "invocation", invocation_id: id}));\n`,
  );
  await chmod(native.binary, 0o700);
  return {
    environment: { TNL_APP_ENDPOINT: descriptor },
    requests,
    faults,
    healthRequests: () => health,
  };
}
