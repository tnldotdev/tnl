import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { expect, test, vi, beforeEach } from "vitest";
import * as z from "zod";
import { environmentSelectionSchema } from "../../src/internal/connector/contract.js";
import { identitySourceSelectionSchema } from "../../src/internal/identity/validation.js";
import type { IdentitySourceReply, IdentitySourceSelection } from "../../src/internal/identity/models.gen.js";

// this owned subprocess/IPC fixture tests the actual native adapter. authority
// verification is separately exercised by the Go visitor client and server.
const fixture = vi.hoisted(() => ({
  children: [] as FakeChild[],
  prepare: [] as { file: string; assertion: string | undefined }[],
  failStop: new Set<string>(),
  stopped: [] as string[],
  wrongProtocol: false,
  wrongPreparedProtocol: false,
  wrongBinding: false,
}));

vi.mock("../../src/internal/native/launcher.js", () => ({ resolveNativeBinary: () => "/fixture/tnl" }));
vi.mock("node:child_process", async (original) => ({
  ...(await original<typeof import("node:child_process")>()),
  spawn(_binary: string, args: string[]) {
    const child = new FakeChild(args);
    fixture.children.push(child);
    return child;
  },
}));
vi.mock("../../src/internal/connector/connection_ipc.js", async (original) => ({
  ...(await original<typeof import("../../src/internal/connector/connection_ipc.js")>()),
  async environmentOwnerIPC(file: string) {
    const child = fixture.children.find((candidate) => candidate.file === file);
    if (child === undefined) throw new Error("unknown owner");
    return {
      async challenge() { return child.challenge("attach"); },
      async prepareIdentity(service: string, reply?: IdentitySourceReply) {
        fixture.prepare.push({ file, assertion: reply?.assertion });
        return child.prepared(service);
      },
      async stop() {
        if (fixture.failStop.has(file)) throw new Error("independent native cleanup failure");
        fixture.stopped.push(file);
        child.kill();
        return { schema: 1, state: "stopping" };
      },
      close() {},
    };
  },
}));

import { environmentClient } from "../../src/internal/connector/environment_client.js";

type Selection = z.infer<typeof environmentSelectionSchema>;
class FakeChild extends EventEmitter {
  readonly pid = fixture.children.length + 100;
  readonly file = `/fixture/owner-${this.pid}/handle.json`;
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly input: unknown[] = [];
  selection?: Selection;
  source?: IdentitySourceSelection;
  killed = false;

  constructor(readonly args: string[]) {
    super();
    this.stdin.on("data", (data: Buffer) => {
      const value: unknown = JSON.parse(data.toString("utf8"));
      this.input.push(value);
      if (this.selection === undefined) {
        const parsed = z.strictObject({ schema: z.literal(1), selection: environmentSelectionSchema, source: identitySourceSelectionSchema, acquisition: z.unknown().optional(), source_environment: z.unknown().optional() }).parse(value);
        this.selection = parsed.selection;
        this.source = parsed.source;
        if (parsed.acquisition === undefined) queueMicrotask(() => this.stdout.write(JSON.stringify(this.challenge("prepare")) + "\n"));
        else queueMicrotask(() => this.ready());
      } else queueMicrotask(() => {
        this.ready();
      });
    });
  }

  ready() {
    this.stdout.end(JSON.stringify({
          schema: 1, state: "ready", pid: this.pid,
          expires_at: new Date(Date.now() + 60_000).toISOString(),
          executable: "/fixture/tnl", connection_handle: this.file,
          project_runtime: this.project(), environment: this.binding(),
    }) + "\n");
  }

  selected() {
    const selection = this.selection;
    if (selection === undefined) throw new Error("selection not captured");
    const service = Object.keys(selection.services)[0];
    if (service === undefined) throw new Error("service missing");
    return { selection, service, protocol: fixture.wrongProtocol ? "http" : selection.services[service] };
  }
  challenge(operation: "prepare" | "attach") {
    const { selection } = this.selected();
    const ref = selection.environment;
    return {
      schema: 1, id: "a".repeat(32), selection, source: this.source, server: ref.server,
      operation: operation === "prepare" ? "visitor_prepare" : "visitor_attach", scope: `machine/v1/${"a".repeat(64)}`,
      binding_digest: "b".repeat(64), expires_at: new Date(Date.now() + 30_000).toISOString(), native_public_key: Buffer.alloc(32, 1).toString("base64url"),
      ...(operation === "prepare" ? { nonce: "n".repeat(32) } : { session_id: `wls_${"a".repeat(22)}` }),
      audience: operation === "prepare"
        ? `${ref.server}/v1/projects/${ref.project_key}/environments/${ref.environment_id}/visitors/prepare`
        : `${ref.server}/v1/environment-visitor-sessions/wls_${"a".repeat(22)}/assertions`,
    };
  }
  binding() {
    const { selection, service, protocol } = this.selected();
    return { environment: selection.environment, applied_definition_revision: 1, mutation_revision: 2,
      services: { [service]: { service_id: `svc_${"a".repeat(22)}`, protocol, endpoint: { hostname: "service.example", port: 5432, public: false } } } };
  }
  project() {
    const { service, protocol } = this.selected();
    return { dev: false, namespace: "service.example", services: { [service]: { namespace: "service.example", hostname: "service.example", port: 5432, public: false, protocol, ...(protocol === "http" ? { url: "https://service.example:5432" } : {}) } } };
  }
  prepared(service: string) {
    const { service: selected, protocol: discovered } = this.selected();
    const protocol = fixture.wrongPreparedProtocol ? "http" : discovered;
    if (service !== selected) throw new Error("service changed after discovery");
    const binding = this.binding();
    if (fixture.wrongBinding) binding.mutation_revision++;
    const project = this.project();
    if (fixture.wrongPreparedProtocol) {
      const metadata = project.services[service];
      if (metadata === undefined) throw new Error("prepared metadata missing");
      metadata.protocol = "http";
      metadata.url = "https://service.example:5432";
    }
    return { schema: 1, project_runtime: project, environment: binding,
      connection: { schema: 1, protocol, host: "127.0.0.1", port: 15432,
        ssl: { servername: "service.example", rejectUnauthorized: true },
        expires_at: new Date(Date.now() + 60_000).toISOString(), transport_id: `ctg_${"a".repeat(22)}`,
        ...(protocol === "http" ? { url: "https://service.example:5432" } : {}),
      } };
  }
  kill() {
    if (!this.killed) { this.killed = true; this.stdout.end(); queueMicrotask(() => this.emit("close", 0, null)); }
    return true;
  }
}

beforeEach(() => {
  fixture.children.length = 0; fixture.prepare.length = 0; fixture.stopped.length = 0;
  fixture.failStop.clear(); fixture.wrongProtocol = false; fixture.wrongPreparedProtocol = false; fixture.wrongBinding = false;
});

const services = Object.freeze({ db: Object.freeze({ protocol: "postgres" }) });
const environment = Object.freeze({ server: "https://control.example", project_key: "project", environment_id: `env_${"a".repeat(22)}` });
function client(assertion: () => Promise<string>) {
  return environmentClient({ services, environment, identity: { kind: "oidc", machine_id: `mci_${"a".repeat(22)}`, permission_id: `mwp_${"a".repeat(22)}`, assertion: async () => ({ token: await assertion(), expiresAt: new Date(Date.now() + 60_000) }) } });
}

test("actual adapter hands proof over private stdin and retains one exact owner across source rotation", async () => {
  let token = "first.private.assertion";
  const selected = client(async () => token);
  try {
    expect((await selected.connect("db")).host).toBe("127.0.0.1");
    token = "rotated.private.assertion";
    await selected.connect("db");
    expect(fixture.children).toHaveLength(1);
    expect(JSON.stringify(fixture.children[0]?.args)).not.toContain("private.assertion");
    expect(fixture.children[0]?.input[0]).toEqual({ schema: 1, source: { kind: "oidc", machine_id: `mci_${"a".repeat(22)}` }, selection: { environment, permission_id: `mwp_${"a".repeat(22)}`, services: { db: "postgres" } } });
    expect(fixture.children[0]?.input[1]).toEqual({ schema: 1, challenge_id: "a".repeat(32), assertion: "first.private.assertion" });
    expect(fixture.prepare.map((value) => value.assertion)).toEqual([undefined, "rotated.private.assertion"]);
  } finally { await selected.close(); }
});

test("wrong discovery and changed preparation binding never return typed settings", async () => {
  const selected = client(async () => "private.assertion");
  fixture.wrongProtocol = true;
  await expect(selected.connect("db")).rejects.toMatchObject({ code: "sdk.response_invalid" });
  expect(fixture.prepare).toHaveLength(0);
  fixture.wrongProtocol = false;
  fixture.wrongPreparedProtocol = true;
  await expect(selected.connect("db")).rejects.toMatchObject({ code: "sdk.response_invalid" });
  fixture.wrongPreparedProtocol = false;
  fixture.wrongBinding = true;
  await expect(selected.connect("db")).rejects.toMatchObject({ code: "sdk.response_invalid" });
  await selected.close();
});

test("source methods retain their private receiver while the selected permission stays captured", async () => {
  class Source {
    readonly kind = "oidc";
    readonly machine_id = `mci_${"a".repeat(22)}`;
    permission_id = `mwp_${"a".repeat(22)}`;
    #assertion = "registered.private.assertion";
    async assertion() { return { token: this.#assertion, expiresAt: new Date(Date.now() + 60_000) }; }
  }
  const source = new Source();
  const selected = environmentClient({ services, environment, identity: source });
  source.permission_id = `mwp_${"b".repeat(22)}`;
  try {
    await selected.connect("db");
    expect(fixture.children[0]?.selection?.permission_id).toBe(`mwp_${"a".repeat(22)}`);
    expect(fixture.children[0]?.input[1]).toMatchObject({ assertion: "registered.private.assertion" });
  } finally { await selected.close(); }
});

test("native acquisition crosses private startup only and does not run a language callback", async () => {
  const source = { kind: "oidc" as const, machine_id: `mci_${"a".repeat(22)}`, permission_id: `mwp_${"a".repeat(22)}`, acquisition: { method: "token-env" as const, token_env: "EXPLICIT_TOKEN" } };
  vi.stubEnv("EXPLICIT_TOKEN", "private.native.token");
  const selected = environmentClient({ services, environment, identity: source });
  vi.stubEnv("EXPLICIT_TOKEN", "later.unrelated.token");
  try {
    await selected.connect("db");
    expect(fixture.children[0]?.input).toHaveLength(1);
    expect(fixture.children[0]?.input[0]).toMatchObject({ source_environment: { token_env: "EXPLICIT_TOKEN", token_value: "later.unrelated.token" } });
    expect(JSON.stringify(fixture.children[0]?.args)).not.toContain("private.native.token");
    expect(fixture.prepare[0]?.assertion).toBeUndefined();
  } finally { await selected.close(); vi.unstubAllEnvs(); }
});

test("independent clients retry exact failed cleanup without stopping a sibling", async () => {
  const first = client(async () => "first.assertion"), second = client(async () => "second.assertion");
  await Promise.all([first.connect("db"), second.connect("db")]);
  const a = fixture.children[0], b = fixture.children[1];
  if (a === undefined || b === undefined) throw new Error("owners missing");
  fixture.failStop.add(a.file);
  await expect(first.close()).rejects.toThrow("environment client cleanup failed");
  expect(b.killed).toBe(false);
  await second.connect("db");
  fixture.failStop.delete(a.file);
  await first.close();
  expect(fixture.stopped).toEqual([a.file]);
  await second.close();
});
