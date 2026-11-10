import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, expect, onTestFinished, test, vi } from "vitest";
import type { TnlApplicationCredential } from "../../src/credential.js";
import type { SelectionOptions } from "../../src/internal/connector/workload/contract.js";

const fixture = vi.hoisted(() => ({
  calls: [] as string[][],
  identity: "A",
  documents: new Map<string, TnlApplicationCredential>(),
  denied: false,
  refreshDenied: false,
  changedKey: false,
  expired: false,
}));

vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/installed/tnl",
}));
vi.mock("node:child_process", () => ({
  execFile(
    _binary: string,
    args: string[],
    _options: unknown,
    callback: (error: Error | null, stdout: string) => void,
  ) {
    fixture.calls.push(args);
    return {
      stdin: {
        on() {},
        end() {
          callback(
            null,
            JSON.stringify(
              args.includes("sdk-workload")
                ? selection()
                : args.includes("sdk-stop")
                  ? { schema: 1, state: "stopped" }
                  : application(fixture.identity, true),
            ),
          );
        },
      },
    };
  },
  execFileSync() {
    throw new Error("unexpected synchronous work");
  },
}));
vi.mock("../../src/internal/connector/connection_ipc.js", () => ({
  ownerIPC: async (file: string) => ({
    async workload() {
      return selection();
    },
    async application(_assertion?: string, options?: SelectionOptions, refresh = false) {
      if (options !== undefined && !refresh) return application(fixture.identity, true);
      const identity = file.includes("/B/") ? "B" : "A";
      if (refresh && (fixture.refreshDenied || identity !== fixture.identity))
        return { schema: 1, reason: "TNL_CLIENT_WORKLOAD_DENIED" };
      return application(identity, false);
    },
    async prepare() {
      return {
        schema: 1,
        owner: owner(fixture.identity),
        prepared: {
          schema: 1,
          project_runtime: {
            dev: false,
            namespace: "example.test",
            services: {
              database: {
                protocol: "postgres",
                hostname: "db.example.test",
                namespace: "example.test",
                port: 15432,
                public: false,
              },
            },
          },
          connection: {
            schema: 1,
            protocol: "postgres",
            host: "127.0.0.1",
            port: 24567,
            expires_at: new Date(Date.now() + 60_000).toISOString(),
            transport_id: `ctg_${"A".repeat(22)}`,
            ssl: { servername: "db.example.test", rejectUnauthorized: true },
          },
        },
      };
    },
    close() {},
  }),
}));

function selection() {
  return {
    schema: 1,
    name: "deploy",
    directory: process.cwd(),
    manifest: "/project/.tnl/generated/workloads.json",
    policy: "a".repeat(64),
    source: "callback",
  };
}
function owner(identity: string) {
  return {
    connection_handle: `/private/${identity}/handle.json`,
    executable: "/installed/tnl",
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
}
function application(identity: string, selected: boolean): unknown {
  const credential = fixture.documents.get(identity);
  if (credential === undefined) throw new Error("missing fixture credential");
  const prepared = {
    schema: 1,
    credential: {
      ...credential,
      ...(fixture.changedKey ? { key_id: `pkey_${"Z".repeat(22)}` } : {}),
    },
    source_session_id: `wls_${identity.repeat(22)}`,
    lease_expires_at: new Date(Date.now() + (fixture.expired ? -1 : 90_000)).toISOString(),
    verification: {
      digest: "d".repeat(64),
      binding: identity.toLowerCase().repeat(64),
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    },
  };
  if (fixture.denied) prepared.credential.grants = [];
  return selected ? { schema: 1, owner: owner(identity), application: prepared } : prepared;
}

beforeEach(() => {
  vi.resetModules();
  vi.stubGlobal("__tnlConnectorContextV3", undefined);
  for (const name of [
    "TNL_WORKLOAD",
    "TNL_CONNECTION_HANDLE",
    "TNL_SERVER",
    "TNL_STATE_DIR",
    "GITHUB_ACTIONS",
    "VERCEL",
    "FLY_APP_NAME",
  ])
    vi.stubEnv(name, undefined);
  const listeners = new Set(process.listeners("beforeExit"));
  onTestFinished(() => {
    for (const listener of process.listeners("beforeExit"))
      if (!listeners.has(listener)) process.off("beforeExit", listener);
  });
  fixture.calls.length = 0;
  fixture.identity = "A";
  fixture.denied = false;
  fixture.refreshDenied = false;
  fixture.changedKey = false;
  fixture.expired = false;
  fixture.documents.clear();
  for (const identity of ["A", "B"]) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    fixture.documents.set(identity, {
      version: 1,
      control_url: "https://control.example",
      client_id: `pub_${identity.repeat(22)}`,
      key_id: `pkey_${identity.repeat(22)}`,
      team_id: "team",
      private_key: Buffer.concat([
        privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32),
        publicKey.export({ type: "spki", format: "der" }).subarray(-32),
      ]).toString("base64url"),
      grants: [
        {
          id: `pgrant_${identity.repeat(22)}`,
          operation: "publish",
          kind: "service",
          service_id: `svc_${"S".repeat(22)}`,
        },
      ],
    });
  }
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

test("workload application acquisition shares the native visitor registry and pins source authorization across A/B/A", async () => {
  const { createConnectionScope, workloadApplication, connectionHandle, closeConnectionScope } =
    await import("../../src/internal/connector/connection.js");
  const token = vi.fn(async () => fixture.identity);
  const scope = createConnectionScope({ credential: { workload: "deploy", token } });
  try {
    const a = await workloadApplication(scope);
    await a.authorize(`svc_${"S".repeat(22)}`);
    const visitor = await connectionHandle("database", vi.fn(), scope);
    expect(visitor).toHaveProperty("port", 24567);
    expect(fixture.calls.filter((args) => args.includes("sdk-application"))).toHaveLength(1);
    expect(fixture.calls.filter((args) => args.includes("sdk-prepare"))).toHaveLength(0);
    fixture.identity = "B";
    const b = await workloadApplication(scope);
    expect(b.credential.private_key).not.toBe(a.credential.private_key);
    await a.authorize(`svc_${"S".repeat(22)}`);
    fixture.identity = "A";
    const again = await workloadApplication(scope);
    expect(again.credential).toEqual(a.credential);
    await again.authorize(`svc_${"S".repeat(22)}`);
    expect(token).toHaveBeenCalled();
  } finally {
    await closeConnectionScope(scope);
  }
});

test.each(["grant", "key", "lease"])(
  "source %s loss cannot borrow another owner or a personal credential",
  async (fault) => {
    const { createConnectionScope, workloadApplication, closeConnectionScope } =
      await import("../../src/internal/connector/connection.js");
    const scope = createConnectionScope({
      credential: { workload: "deploy", token: async () => "A" },
    });
    try {
      const source = await workloadApplication(scope);
      fixture.refreshDenied = true;
      await source.authorize(`svc_${"S".repeat(22)}`);
      if (fault === "grant") fixture.denied = true;
      if (fault === "key") fixture.changedKey = true;
      if (fault === "lease") fixture.expired = true;
      await expect(source.authorize(`svc_${"S".repeat(22)}`)).rejects.toHaveProperty(
        "code",
        "sdk.workload_denied",
      );
      expect(fixture.calls.filter((args) => args.includes("sdk-application"))).toHaveLength(1);
    } finally {
      await closeConnectionScope(scope);
    }
  },
);
