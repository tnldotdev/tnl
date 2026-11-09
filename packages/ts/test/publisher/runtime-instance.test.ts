import { generateKeyPairSync } from "node:crypto";
import { beforeEach, expect, test, vi } from "vitest";
import type { TnlApplicationCredential } from "@tnldotdev/tnl";

const fixture = vi.hoisted(() => ({
  order: [] as string[],
  selected: undefined as AbortSignal | undefined,
  gate: undefined as Promise<void> | undefined,
  fail: false,
  workload: false,
  source: undefined as { document: string; resource: string; server: string } | undefined,
  scope: {
    key: "scope",
    directory: "/project",
    environment: {},
    cleanup: undefined as (() => Promise<void>) | undefined,
  },
}));
vi.mock("../../src/internal/connector/connection_bridge.js", () => ({
  loadConnection: () => ({
    createConnectionScope: () => fixture.scope,
    closeConnectionScope: async () => {
      fixture.order.push("connector");
    },
    connectionHandle: () => ({}),
    connectionClient: () => ({}),
    usesWorkload: () => fixture.workload,
  }),
}));
vi.mock("../../src/internal/publisher/publish.js", () => ({
  publishServer: vi.fn(),
  publishFetch: async (
    _server: unknown,
    options: { signal: AbortSignal },
    _runtime: unknown,
    source?: { document: string; resource: string; server: string },
  ) => {
    fixture.selected = options.signal;
    fixture.source = source;
    await fixture.gate;
    return {
      async close() {
        fixture.order.push("publication");
        if (fixture.fail) throw new Error("drain failed");
      },
    };
  },
}));
vi.mock("../../src/internal/publisher/app_credential.js", () => ({
  prepareApplicationPublication: async (source: {
    document: string;
    resource: string;
    server: string;
  }) => {
    fixture.source = source;
    await fixture.gate;
    return {
      async close() {
        fixture.order.push("preparation");
        if (fixture.fail) throw new Error("drain failed");
      },
    };
  },
}));

beforeEach(() => {
  fixture.order.length = 0;
  fixture.selected = undefined;
  fixture.gate = undefined;
  fixture.fail = false;
  fixture.workload = false;
  fixture.source = undefined;
});

function applicationCredential(): TnlApplicationCredential {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const key = Buffer.concat([
    privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32),
    publicKey.export({ type: "spki", format: "der" }).subarray(-32),
  ]);
  return {
    version: 1,
    control_url: "https://control.example",
    client_id: `pub_${"A".repeat(22)}`,
    key_id: `pkey_${"A".repeat(22)}`,
    team_id: "team",
    private_key: key.toString("base64url"),
    grants: [
      {
        id: `pgrant_${"A".repeat(22)}`,
        operation: "publish",
        kind: "saved_public_url",
        public_url_id: `url_${"A".repeat(22)}`,
      },
      {
        id: `pgrant_${"B".repeat(22)}`,
        operation: "publish",
        kind: "saved_public_url",
        public_url_id: `url_${"B".repeat(22)}`,
      },
    ],
  };
}

test("application publication pins the prepared document and exact resource before native work", async () => {
  const { createTnl } = await import("../../src/index.js");
  const credential = applicationCredential();
  const app = createTnl({ credential });
  const resource = `url_${"B".repeat(22)}` as const;
  Reflect.set(credential, "control_url", "https://another.example");
  try {
    await app.publish(() => new Response("app"), { resource });
    expect(fixture.source).toMatchObject({ server: "https://control.example", resource });
    expect(JSON.parse(fixture.source?.document ?? "")).toMatchObject({
      client_id: credential.client_id,
      key_id: credential.key_id,
      control_url: "https://control.example",
      grants: credential.grants,
    });
    expect(fixture.selected).toBeDefined();
  } finally {
    await app.close();
  }
  expect(fixture.order).toEqual(["publication", "connector"]);
});

test("application publication refuses ambiguous grants and explicit source changes without fallback", async () => {
  const { createTnl } = await import("../../src/index.js");
  const credential = applicationCredential();
  const app = createTnl({ credential });
  try {
    await expect(app.publish(() => new Response("app"))).rejects.toHaveProperty(
      "code",
      "sdk.credential_denied",
    );
    await expect(
      app.publish(() => new Response("app"), { resource: `url_${"X".repeat(22)}` }),
    ).rejects.toHaveProperty("code", "sdk.credential_denied");
    await expect(
      app.publish(() => new Response("app"), {
        resource: `url_${"A".repeat(22)}`,
        server: "https://another.example",
      }),
    ).rejects.toHaveProperty("code", "sdk.credential_denied");
    await expect(
      app.publish(() => new Response("app"), {
        resource: `url_${"A".repeat(22)}`,
        publisherCredentialFile: "/private/another.json",
      }),
    ).rejects.toHaveProperty("code", "sdk.credential_denied");
    expect(fixture.selected).toBeUndefined();
    expect(fixture.source).toBeUndefined();
  } finally {
    await app.close();
  }
  const visit = createTnl({
    credential: {
      ...credential,
      grants: [
        {
          id: `pgrant_${"V".repeat(22)}`,
          operation: "visit",
          kind: "saved_public_url",
          public_url_id: `url_${"A".repeat(22)}`,
        },
      ],
    },
  });
  try {
    await expect(visit.publish(() => new Response("app"))).rejects.toHaveProperty(
      "code",
      "sdk.credential_denied",
    );
  } finally {
    await visit.close();
  }
  expect(fixture.source).toBeUndefined();
});

test("application preparation selects the same pinned exact publish grant and retains failed drain for retry", async () => {
  const { createTnl } = await import("../../src/index.js");
  const credential = applicationCredential();
  const app = createTnl({ credential });
  try {
    await expect(app.prepare()).rejects.toHaveProperty("code", "sdk.credential_denied");
    expect(fixture.source).toBeUndefined();
    const resource = `url_${"B".repeat(22)}` as const;
    await app.prepare({ resource });
    expect(fixture.source).toMatchObject({ resource, server: credential.control_url });
    fixture.fail = true;
    await expect(app.close()).rejects.toBeInstanceOf(AggregateError);
    expect(fixture.order).toEqual(["preparation"]);
    fixture.fail = false;
    await app.close();
    expect(fixture.order).toEqual(["preparation", "preparation", "connector"]);
  } finally {
    fixture.fail = false;
    await app.close();
  }
});

test("application HTTP service publication and preparation select an exact service grant, never a URL or visit grant", async () => {
  const { createTnl } = await import("../../src/index.js");
  const resource = `svc_${"S".repeat(22)}` as const;
  const credential: TnlApplicationCredential = {
    ...applicationCredential(),
    grants: [
      {
        id: `pgrant_${"P".repeat(22)}`,
        operation: "publish",
        kind: "service",
        service_id: resource,
      },
      { id: `pgrant_${"V".repeat(22)}`, operation: "visit", kind: "service", service_id: resource },
    ],
  };
  const app = createTnl({ credential });
  try {
    await app.publish(() => new Response("app"));
    expect(fixture.source?.resource).toBe(resource);
    await app.prepare({ resource });
    expect(fixture.source?.resource).toBe(resource);
    await expect(
      app.publish(() => new Response("app"), { resource: `url_${"S".repeat(22)}` }),
    ).rejects.toHaveProperty("code", "sdk.credential_denied");
  } finally {
    await app.close();
  }
});

test("a selected workload cannot fall back to a human publisher", async () => {
  const { createTnl } = await import("../../src/index.js");
  fixture.workload = true;
  const app = createTnl();
  await expect(app.publish(() => new Response("app"))).rejects.toHaveProperty(
    "code",
    "sdk.workload_denied",
  );
  await expect(app.prepare()).rejects.toHaveProperty("code", "sdk.workload_denied");
  expect(fixture.selected).toBeUndefined();
  expect(fixture.order).toEqual([]);
  await app.close();
});

test("instance cleanup drains publications before releasing connector clients", async () => {
  const { createTnl } = await import("../../src/index.js");
  const app = createTnl();
  await app.publish(() => new Response("app"));
  await app.close();
  expect(fixture.order).toEqual(["publication", "connector"]);
  expect(fixture.selected?.aborted).toBe(false);
  expect(() => app.connect("database")).toThrow(
    expect.objectContaining({ code: "sdk.client_closed" }),
  );
});

test("failed publication drain retains connector ownership for cleanup retry", async () => {
  const { createTnl } = await import("../../src/index.js");
  const app = createTnl();
  await app.publish(() => new Response("app"));
  fixture.fail = true;
  await expect(app.close()).rejects.toBeInstanceOf(AggregateError);
  expect(fixture.order).toEqual(["publication"]);
  fixture.fail = false;
  await app.close();
  expect(fixture.order).toEqual(["publication", "publication", "connector"]);
});

test("instance cleanup joins pending publication creation and closes its late result", async () => {
  const { createTnl } = await import("../../src/index.js");
  const gate = Promise.withResolvers<void>();
  fixture.gate = gate.promise;
  const app = createTnl();
  const publishing = app.publish(() => new Response("app"));
  const rejected = publishing.catch((error: unknown) => error);
  await vi.waitFor(() => expect(fixture.selected).toBeDefined());
  const closing = app.close();
  expect(fixture.selected?.aborted).toBe(true);
  expect(fixture.order).toEqual([]);
  gate.resolve();
  expect(await rejected).toHaveProperty("code", "sdk.client_closed");
  await closing;
  expect(fixture.order).toEqual(["publication", "connector"]);
});
