import { beforeEach, expect, test, vi } from "vitest";

const fixture = vi.hoisted(() => ({
  order: [] as string[],
  selected: undefined as AbortSignal | undefined,
  gate: undefined as Promise<void> | undefined,
  fail: false,
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
  }),
}));
vi.mock("../../src/internal/publisher/publish.js", () => ({
  publishServer: vi.fn(),
  publishFetch: async (_server: unknown, options: { signal: AbortSignal }) => {
    fixture.selected = options.signal;
    await fixture.gate;
    return {
      async close() {
        fixture.order.push("publication");
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
