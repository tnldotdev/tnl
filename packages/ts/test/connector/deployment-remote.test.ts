import { afterEach, describe, expect, it, vi } from "vitest";
import { createClient } from "../../src/internal/connector/client.js";

const native = vi.hoisted(() => ({
  selections: [] as {
    selection: unknown;
    close: ReturnType<typeof vi.fn>;
    acquire: ReturnType<typeof vi.fn>;
  }[],
  accesses: vi.fn(),
}));
vi.mock("../../src/internal/connector/connection.js", () => ({
  deploymentAccess: native.accesses,
  deploymentConnector(selection: unknown) {
    const owner = {
      selection,
      close: vi.fn(async () => {}),
      acquire: vi.fn(async () => ({
        key: "owner-binding",
        protocol: "postgres",
        connection: {
          host: "127.0.0.1",
          port: 15432,
          ssl: { servername: "db.example.test", rejectUnauthorized: true },
        },
      })),
    };
    native.selections.push(owner);
    return owner;
  },
}));
vi.mock("../../src/internal/native/launcher.js", () => ({
  resolveNativeBinary: () => "/fixture/tnl",
}));
afterEach(() => {
  vi.unstubAllGlobals();
  native.selections = [];
  native.accesses.mockReset();
});
const services = { db: { protocol: "postgres" } } as const;

describe("project-bound deployment handles", () => {
  it("captures independent selections and closes only its own driver factories and native owner", async () => {
    const app = createClient({ project: "acme/shop", token: "portable-private", services });
    const production = app.deployment("production");
    const customer = app.deployment("pgrp_aaaaaaaaaaaaaaaaaaaaaa");
    const create = vi.fn((connection) => ({ connection }));
    const close = vi.fn();
    const first = production.client("db", { create, close });
    const second = customer.client("db", { create, close });
    expect(await first()).toBe(await first());
    const sibling = await second();
    expect(native.selections.map((value) => value.selection)).toEqual([
      { project: "acme/shop", token: "portable-private", name: "production", services: ["db"] },
      {
        project: "acme/shop",
        token: "portable-private",
        name: "pgrp_aaaaaaaaaaaaaaaaaaaaaa",
        services: ["db"],
      },
    ]);
    await production.close();
    expect(close).toHaveBeenCalledTimes(1);
    expect(native.selections[0]?.close).toHaveBeenCalledOnce();
    expect(native.selections[1]?.close).not.toHaveBeenCalled();
    expect(await second()).toBe(sibling);
    await expect(production.connect("db")).rejects.toMatchObject({ code: "sdk.client_closed" });
    await customer.close();
    expect(close).toHaveBeenCalledTimes(2);
  });

  it("rejects protocol drift before calling an ordinary driver factory", async () => {
    const deployment = createClient({
      project: "acme/shop",
      token: "private",
      services,
    }).deployment("production");
    native.selections[0]?.acquire.mockResolvedValue({
      key: "changed",
      protocol: "mysql",
      connection: {},
    });
    const create = vi.fn();
    await expect(deployment.client("db", { create, close: vi.fn() })()).rejects.toMatchObject({
      code: "sdk.response_invalid",
    });
    expect(create).not.toHaveBeenCalled();
    await deployment.close();
  });

  it("composes stock management methods with native signing and original request conditions", async () => {
    const expires_at = Date.now() + 60_000;
    native.accesses.mockResolvedValue({
      schema: 1,
      server: "https://control.example.test",
      team_id: "tm_selected",
      project_key: "shop",
      token: "pta_scoped",
      expires_at,
    });
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      Object.assign(
        async (input: Request) => {
          requests.push(input);
          if (input.method === "DELETE") return new Response(null, { status: 204 });
          return Response.json(
            {
              id: "pgrp_customer",
              team_id: "tm_selected",
              project_key: "shop",
              name: "customer",
              revision: 1,
              targets: { db: { address: "db.internal:5432" } },
              services: {
                db: { id: "svc_aaaaaaaaaaaaaaaaaaaaaa", protocol: "postgres", trust_revision: 1 },
              },
            },
            { status: input.method === "POST" ? 201 : 200, headers: { ETag: '"1"' } },
          );
        },
        { preconnect() {} },
      ),
    );
    const app = createClient({ project: "acme/shop", token: "portable-private" });
    const customer = await app.deployments.create(
      { name: "customer", targets: { db: { address: "db.internal:5432" } } },
      { idempotencyKey: "original" },
    );
    await app.deployments.update(
      customer.id,
      { targets: { db: { address: "changed:5432" } } },
      { ifMatch: customer.etag },
    );
    await app.deployments.delete(customer.id, { ifMatch: customer.etag });
    expect(native.accesses).toHaveBeenCalledExactlyOnceWith("acme/shop", "portable-private");
    expect(native.selections).toHaveLength(0);
    expect(requests.map((request) => request.headers.get("authorization"))).toEqual([
      "Bearer pta_scoped",
      "Bearer pta_scoped",
      "Bearer pta_scoped",
    ]);
    expect(requests[0]?.headers.get("idempotency-key")).toBe("original");
    expect(requests[1]?.headers.get("if-match")).toBe('"1"');
    expect(new URL(requests[0]?.url ?? "").searchParams.get("team_id")).toBe("tm_selected");
  });
});
