import { inspect } from "node:util";
import { afterEach, expect, test, vi } from "vitest";
import { createClient } from "../helpers/portable-client.js";
import { connect, deployment as browserDeployment, publish } from "../../src/browser.js";
import { response } from "../../src/index.js";
import type { WasmPublisherHost } from "../../src/internal/connector/wasm_abi.js";
import type { PublisherStorage } from "../../src/internal/portable/storage.js";
import {
  DurableObjectPublisher,
  type DurableObjectPublisherState,
  type DurableObjectWasmPublisherOptions,
} from "../../src/durable-object.js";
import { durablePublisherDeployment } from "../../src/internal/portable/durable-deployment.js";
import { portableSQLite } from "../helpers/portable-sqlite.js";

const mocks = vi.hoisted(() => ({ load: vi.fn(), browserStorage: vi.fn() }));
vi.mock("../../src/internal/connector/wasm_loader.js", () => ({ loadWasm: mocks.load }));
vi.mock("../../src/internal/portable/storage-browser.js", () => ({
  createBrowserPublisherStorage: mocks.browserStorage,
}));

function storage() {
  const records = new Map<string, Uint8Array>();
  return {
    get: vi.fn(async (key: string) => records.get(key)?.slice()),
    put: vi.fn(async (key: string, bytes: Uint8Array) => {
      records.set(key, bytes.slice());
    }),
    delete: vi.fn(async (key: string) => {
      records.delete(key);
    }),
    sync: vi.fn(async () => {}),
    async withLock<Value>(_key: string, operation: () => Promise<Value>) {
      return operation();
    },
    close: vi.fn(async () => {}),
  } satisfies PublisherStorage & { close(): Promise<void> };
}

function deferred<Value = void>() {
  const value = Promise.withResolvers<Value>();
  void value.promise.catch(() => {});
  return value;
}

function fixture() {
  const exited = deferred();
  const publications: ReturnType<typeof publication>[] = [];
  const events: string[] = [];
  const connection = {
    metadata: { key: "db:binding", protocol: "postgres", hostname: "db.example.test" },
    open: vi.fn(),
    fetch: vi.fn(),
    close: vi.fn(async () => {
      events.push("connection:close");
    }),
  };
  const connector = {
    connect: vi.fn(async () => connection),
    close: vi.fn(async () => {
      events.push("connector:close");
    }),
  };
  function publication(encoded: string, host: WasmPublisherHost) {
    const ready = deferred();
    const closed = deferred();
    ready.resolve();
    const raw = {
      url: "https://app.example.test",
      run: {
        serviceID: `svc_${"S".repeat(22)}`,
        serviceRunID: `srun_${"R".repeat(22)}`,
        runNumber: "1",
      },
      ready: ready.promise,
      closed: closed.promise,
      close: vi.fn(async () => {
        events.push("publication:close");
        ready.reject(new DOMException("stopped", "AbortError"));
        closed.resolve();
      }),
    };
    return { encoded, host, ready, closed, raw };
  }
  const bridge = {
    createDeployment: vi.fn(async () => connector),
    publish: vi.fn(async (encoded: string, host: WasmPublisherHost): Promise<unknown> => {
      const value = publication(encoded, host);
      publications.push(value);
      return value.raw;
    }),
    close: vi.fn(async () => {
      events.push("runtime:close");
      exited.resolve();
    }),
  };
  const store = storage();
  mocks.load.mockResolvedValue({ bridge, exited: exited.promise });
  mocks.browserStorage.mockReturnValue(store);
  return { bridge, connector, connection, publications, events, store, publication };
}

function deployment() {
  return createClient({
    project: "acme/shop",
    token: "private-credential",
    services: { app: { protocol: "http" }, db: { protocol: "postgres" } },
  }).deployment("production");
}

function createDurableObjectPublisher(
  state: DurableObjectPublisherState,
  options: DurableObjectWasmPublisherOptions,
) {
  const module = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
  return new DurableObjectPublisher(state, {
    ...options,
    createDeployment: (context) => durablePublisherDeployment(context, module),
  });
}

afterEach(() => {
  mocks.load.mockReset();
  mocks.browserStorage.mockReset();
});

test("browser loads publisher WASM only when publish is called", async () => {
  fixture();
  const remote = browserDeployment("production", {
    project: "acme/shop",
    token: "private-credential",
    services: { app: { protocol: "http" }, db: { protocol: "postgres" } },
  });
  expect(mocks.load).not.toHaveBeenCalled();
  await connect(remote, "db");
  expect(mocks.load).toHaveBeenCalledExactlyOnceWith(
    new URL("../../src/wasm/connector.wasm", import.meta.url),
  );
  await publish(remote, "app", () => new Response());
  expect(mocks.load).toHaveBeenNthCalledWith(
    2,
    new URL("../../src/wasm/publisher.wasm", import.meta.url),
  );
  await remote.close();
});

test("named publication uses the publisher ABI and browser storage by default", async () => {
  const f = fixture();
  const remote = deployment();
  const handler = vi.fn((request: Request) =>
    response(request.headers.get("cookie"), {
      headers: [
        ["set-cookie", "one=1"],
        ["set-cookie", "two=2"],
      ],
    }),
  );
  const published = await remote.publish("app", handler, { telemetry: false });
  expect(published.url).toBe("https://app.example.test");
  expect(published.run).toEqual({
    serviceID: `svc_${"S".repeat(22)}`,
    serviceRunID: `srun_${"R".repeat(22)}`,
    runNumber: "1",
  });
  expect(Object.isFrozen(published.run)).toBe(true);
  const started = f.publications[0];
  if (started === undefined) throw new Error("missing publication");
  expect(JSON.parse(started.encoded)).toEqual({
    project: "acme/shop",
    deployment: "production",
    credential: "private-credential",
    service: "app",
  });
  expect(mocks.browserStorage).toHaveBeenCalledOnce();
  expect(f.bridge.createDeployment).not.toHaveBeenCalled();
  expect(started.host.controlFetch).not.toBe(started.host.fetch);
  const request = new Request("https://app.example.test/");
  Object.defineProperty(request, "headers", { value: new Headers({ cookie: "private-cookie" }) });
  const result = await started.host.fetch(request);
  expect(handler).toHaveBeenCalledOnce();
  expect(request.clone().headers.get("cookie")).toBe("private-cookie");
  expect(await result.text()).toBe("private-cookie");
  expect(result.headers.getSetCookie()).toEqual(["one=1", "two=2"]);
  expect(JSON.stringify(published)).not.toContain("private-credential");
  await published.close();
  await published.wait();
  await expect(started.host.fetch(new Request("https://app.example.test/"))).rejects.toMatchObject({
    name: "AbortError",
  });
  expect(handler).toHaveBeenCalledOnce();
  expect(f.bridge.close).not.toHaveBeenCalled();
  await remote.close();
  expect(f.bridge.close).toHaveBeenCalledOnce();
  expect(f.store.close).toHaveBeenCalledOnce();
});

test("portable run aliases retain immutable exact metadata without number rounding", async () => {
  const f = fixture();
  const remote = deployment();
  const reference = {
    serviceID: `svc_${"S".repeat(22)}`,
    serviceRunID: `srun_${"R".repeat(22)}`,
    runNumber: "9223372036854775807",
  };
  f.bridge.publish.mockImplementation(async (encoded, host) => {
    const started = f.publication(encoded, host);
    f.publications.push(started);
    return {
      ...started.raw,
      run: reference,
      publisherURL: "https://p-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test",
    };
  });
  const published = await remote.publish("app", () => new Response("app"));
  expect(published.publisherURL).toBe("https://p-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test");
  expect(published.run).toEqual(reference);
  reference.serviceRunID = `srun_${"X".repeat(22)}`;
  expect(published.run?.serviceRunID).toBe(`srun_${"R".repeat(22)}`);
  await remote.close();
});

test("temporary publication forwards visitor policy and limits without another authority model", async () => {
  const f = fixture();
  const remote = deployment();
  const published = await remote.publish(() => new Response("temporary"), {
    requirePostQuantum: true,
    access: { mode: "anonymous", ip: ["192.0.2.0/24"] },
    limits: { requests: 50, concurrency: 3, rate: { requests: 7, per: "1m" } },
  });
  expect(JSON.parse(f.publications[0]?.encoded ?? "")).toEqual({
    project: "acme/shop",
    deployment: "production",
    credential: "private-credential",
    temporary: {
      require_post_quantum: true,
      access_mode: "anonymous",
      ip: ["192.0.2.0/24"],
      limits: { total: 50, concurrency: 3, rate: { count: 7, per: "1m" } },
    },
  });
  await published[Symbol.asyncDispose]();
  await remote.close();
});

test("publishing and connecting load separate modules without requesting publish-only connect grants", async () => {
  const f = fixture();
  const remote = deployment();
  await Promise.all([remote.publish("app", () => new Response("app")), remote.connect("db")]);
  expect(mocks.load.mock.calls).toEqual(
    expect.arrayContaining([
      [new URL("https://fixture.test/connector.wasm")],
      [new URL("https://fixture.test/publisher.wasm")],
    ]),
  );
  expect(mocks.load).toHaveBeenCalledTimes(2);
  expect(f.bridge.createDeployment).toHaveBeenCalledWith(
    { project: "acme/shop", name: "production", credential: "private-credential", services: [] },
    expect.any(Object),
    expect.any(AbortSignal),
  );
  await remote.close();
  expect(f.connection.close).toHaveBeenCalledOnce();
  expect(f.connector.close).toHaveBeenCalledOnce();
  expect(f.publications[0]?.raw.close).toHaveBeenCalledOnce();
  expect(f.bridge.close).toHaveBeenCalledTimes(2);
  expect(f.events.at(-1)).toBe("runtime:close");
});

test("connect-only clients never initialize publisher storage", async () => {
  const f = fixture();
  const remote = deployment();
  await remote.connect("db");
  expect(mocks.browserStorage).not.toHaveBeenCalled();
  await remote.close();
  expect(f.store.close).not.toHaveBeenCalled();
});

test("supplied publisher storage remains application-owned", async () => {
  const f = fixture();
  const custom = storage();
  const remote = createClient({
    project: "acme/shop",
    token: "private",
    publisherStorage: custom,
  }).deployment("production");
  await remote.publish(() => new Response());
  expect(mocks.browserStorage).not.toHaveBeenCalled();
  await remote.close();
  expect(custom.close).not.toHaveBeenCalled();
  expect(f.bridge.close).toHaveBeenCalledOnce();
});

test("unsupported native listener options and non-HTTP declarations reject before WASM startup", async () => {
  fixture();
  const remote = deployment();
  await expect(
    remote.publish("app", () => new Response(), { targetHostname: "localhost" }),
  ).rejects.toMatchObject({ code: "sdk.capability_unsupported" });
  await expect(
    remote.publish("app", () => new Response(), { telemetry: true }),
  ).rejects.toMatchObject({ code: "sdk.capability_unsupported" });
  // @ts-expect-error only declared HTTP services can be published by a handler.
  await expect(remote.publish("db", () => new Response())).rejects.toMatchObject({
    code: "sdk.configuration_invalid",
  });
  await expect(
    remote.publish("app", () => new Response(), {
      // @ts-expect-error named publication cannot replace saved visitor policy.
      access: "anonymous",
    }),
  ).rejects.toMatchObject({ code: "sdk.configuration_invalid" });
  expect(mocks.load).not.toHaveBeenCalled();
  await remote.close();
});

test("close during pre-readiness startup aborts and joins the exact Go publication", async () => {
  const f = fixture();
  const entered = deferred();
  const ready = deferred();
  const closed = deferred();
  const close = vi.fn(async () => {
    ready.reject(new Error("publisher stopped before readiness"));
    closed.resolve();
  });
  f.bridge.publish.mockImplementationOnce(async () => {
    entered.resolve();
    return { url: "https://app.example.test", ready: ready.promise, closed: closed.promise, close };
  });
  const remote = deployment();
  const pending = remote.publish("app", () => new Response());
  const rejected = expect(pending).rejects.toMatchObject({ code: "sdk.client_closed" });
  await entered.promise;
  const cleanup = remote.close();
  await Promise.all([rejected, cleanup]);
  expect(close).toHaveBeenCalledOnce();
  expect(f.bridge.close).toHaveBeenCalledOnce();
});

test("late startup acknowledgments remain owned when close races acquisition", async () => {
  const f = fixture();
  const entered = deferred();
  const acquired = deferred<unknown>();
  f.bridge.publish.mockImplementationOnce(async () => {
    entered.resolve();
    return acquired.promise;
  });
  const remote = deployment();
  const pending = remote.publish(() => new Response());
  const rejected = expect(pending).rejects.toMatchObject({ code: "sdk.client_closed" });
  await entered.promise;
  let joined = false;
  const cleanup = remote.close().then(() => {
    joined = true;
  });
  await Promise.resolve();
  expect(joined).toBe(false);
  const closed = deferred();
  const close = vi.fn(async () => {
    closed.resolve();
  });
  acquired.resolve({
    url: "https://app.example.test",
    ready: Promise.resolve(),
    closed: closed.promise,
    close,
  });
  await Promise.all([rejected, cleanup]);
  expect(close).toHaveBeenCalledOnce();
  expect(f.bridge.close).toHaveBeenCalledOnce();
});

test("publication and deployment close wait for Go's joined closed promise", async () => {
  const f = fixture();
  const closed = deferred();
  const close = vi.fn(async () => {});
  f.bridge.publish.mockResolvedValueOnce({
    url: "https://app.example.test",
    run: {
      serviceID: `svc_${"S".repeat(22)}`,
      serviceRunID: `srun_${"R".repeat(22)}`,
      runNumber: "1",
    },
    ready: Promise.resolve(),
    closed: closed.promise,
    close,
  });
  const remote = deployment();
  const publication = await remote.publish(() => new Response());
  let joined = false;
  const stopping = publication.close().then(() => {
    joined = true;
  });
  const cleanup = remote.close();
  await Promise.resolve();
  expect(joined).toBe(false);
  expect(f.bridge.close).not.toHaveBeenCalled();
  closed.resolve();
  await Promise.all([stopping, cleanup]);
  expect(close).toHaveBeenCalledOnce();
  expect(f.bridge.close).toHaveBeenCalledOnce();
});

test("closing one publishing deployment never stops a sibling Go runtime", async () => {
  const a = fixture();
  const first = deployment();
  await first.publish(() => new Response("first"));
  const b = fixture();
  const sibling = deployment();
  await sibling.publish(() => new Response("sibling"));
  await first.close();
  expect(a.bridge.close).toHaveBeenCalledOnce();
  expect(b.bridge.close).not.toHaveBeenCalled();
  expect(b.publications[0]?.raw.close).not.toHaveBeenCalled();
  const host = b.publications[0]?.host;
  if (host === undefined) throw new Error("missing sibling host");
  expect(await (await host.fetch(new Request("https://app.example.test/"))).text()).toBe("sibling");
  await sibling.close();
});

test("startup errors and independent cleanup failures are both preserved and redacted", async () => {
  const f = fixture();
  const ready = deferred();
  const closed = deferred();
  const entered = deferred();
  const close = vi.fn(async () => {
    closed.resolve();
    throw new Error("private-credential: cleanup-secret");
  });
  f.bridge.publish.mockImplementationOnce(async () => {
    entered.resolve();
    return { url: "https://app.example.test", ready: ready.promise, closed: closed.promise, close };
  });
  const remote = deployment();
  const pending = remote.publish(() => new Response());
  const failed = expect(pending).rejects.toMatchObject({
    errors: [
      expect.objectContaining({ code: "sdk.publication_failed" }),
      expect.objectContaining({ code: "sdk.publication_cleanup_failed" }),
    ],
  });
  await entered.promise;
  ready.reject(new Error("private-credential: startup-secret"));
  await failed;
  try {
    await pending;
  } catch (error) {
    expect(inspect(error)).not.toContain("private-credential");
    expect(inspect(error)).not.toContain("cleanup-secret");
    expect(inspect(error)).not.toContain("startup-secret");
  }
  await expect(remote.close()).rejects.toMatchObject({ code: "sdk.publication_cleanup_failed" });
  // closed settled, so go's run and host cleanup were joined despite the failure.
  expect(f.bridge.close).toHaveBeenCalledOnce();
});

test("cancellation never hides an independent startup cleanup failure", async () => {
  const f = fixture();
  const entered = deferred();
  const ready = deferred();
  const closed = deferred();
  f.bridge.publish.mockImplementationOnce(async () => {
    entered.resolve();
    return {
      url: "https://app.example.test",
      ready: ready.promise,
      closed: closed.promise,
      async close() {
        ready.reject(new DOMException("canceled", "AbortError"));
        closed.resolve();
        throw new Error("private-credential cleanup-secret");
      },
    };
  });
  const remote = deployment();
  const pending = remote.publish(() => new Response());
  const rejected = expect(pending).rejects.toMatchObject({
    errors: [
      expect.objectContaining({ name: "AbortError" }),
      expect.objectContaining({ code: "sdk.publication_cleanup_failed" }),
    ],
  });
  await entered.promise;
  const cleanup = remote.close();
  const cleanupFailed = expect(cleanup).rejects.toBeInstanceOf(AggregateError);
  await Promise.all([rejected, cleanupFailed]);
  expect(f.bridge.close).toHaveBeenCalledOnce();
  try {
    await cleanup;
  } catch (error) {
    expect(inspect(error)).not.toContain("private-credential");
    expect(inspect(error)).not.toContain("cleanup-secret");
  }
});

test("closed publications do not consume retained-publication capacity forever", async () => {
  fixture();
  const remote = deployment();
  for (let index = 0; index < 70; index++)
    await (await remote.publish(() => new Response())).close();
  await remote.close();
});

test("the durable convenience factory uses persisted identity, SQLite host storage, and the same publisher ABI", async () => {
  const sqlite = portableSQLite();
  try {
    const f = fixture();
    const identity = vi.fn(() => new TextEncoder().encode("private-credential"));
    const options = {
      configuration: { project: "acme/shop", deployment: "production", service: "app" },
      identity,
      handler: () => () => new Response("durable"),
    };
    const first = createDurableObjectPublisher(sqlite.state, options);
    await first.ready;
    const published = await first.start();
    expect(f.bridge.publish).toHaveBeenCalledOnce();
    const host = f.publications[0]?.host;
    if (host === undefined) throw new Error("missing durable host");
    const scope = JSON.stringify({
      control_url: "https://control.example.test",
      team_id: "tm_team",
      publisher_identity_id: "pub_identity",
    });
    const release = await host.storage.lock(scope, "certificate", new AbortController().signal);
    await host.storage.write(
      scope,
      "certificate",
      new Uint8Array([1, 2]),
      new AbortController().signal,
    );
    await host.storage.sync(scope, "certificate", new AbortController().signal);
    await release();
    expect(mocks.browserStorage).not.toHaveBeenCalled();
    await published.close();
    const secondRuntime = fixture();
    const second = createDurableObjectPublisher(sqlite.state, options);
    await second.ready;
    const restarted = await second.start();
    expect(identity).toHaveBeenCalledOnce();
    const restored = secondRuntime.publications[0]?.host;
    if (restored === undefined) throw new Error("missing restarted host");
    expect(
      await restored.storage.read(scope, "certificate", 16, new AbortController().signal),
    ).toEqual(new Uint8Array([1, 2]));
    await restarted.close();
    expect(
      JSON.stringify(sqlite.database.prepare("SELECT key FROM tnl_publisher_records_v1").all()),
    ).not.toContain("private-credential");
  } finally {
    sqlite.close();
  }
});
