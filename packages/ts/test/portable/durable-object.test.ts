import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, expect, expectTypeOf, test } from "vitest";
import type { Deployment } from "../../src/internal/connector/client.js";
import {
  DurableObjectPublisher,
  createDurableObjectPublisherStorage,
  type DurableObjectPublisherOptions,
  type DurablePublisherDeployment,
} from "../../src/durable-object.js";
import type { FetchHandler } from "../../src/internal/publisher/fetch_types.js";
import type {
  NamedPublicationOptions,
  Publication,
  TemporaryPublicationOptions,
} from "../../src/internal/publisher/publication.js";
import { portableDeferred, portableSQLite } from "../helpers/portable-sqlite.js";

const fixtures: ReturnType<typeof portableSQLite>[] = [];
const directories: string[] = [];
afterEach(async () => {
  for (const fixture of fixtures.splice(0)) fixture.close();
  for (const directory of directories.splice(0)) await rm(directory, { recursive: true });
});
function sqlite(filename?: string) {
  const fixture = portableSQLite(filename);
  fixtures.push(fixture);
  return fixture;
}
const configuration = {
  project: "project",
  deployment: "preview",
  service: "app",
  options: { telemetry: false },
} as const;
const intentKey = "@tnl/publisher-owner/v1";

test("the lifetime owner accepts the existing typed deployment API", () => {
  expectTypeOf<Deployment<{ app: { protocol: "http" } }>>().toExtend<DurablePublisherDeployment>();
});

function runtime() {
  let created = 0;
  let identities = 0;
  let published = 0;
  let closed = 0;
  let handler: FetchHandler | undefined;
  let complete = portableDeferred();
  let ended = portableDeferred();
  let failure: unknown;
  let onClose: (() => Promise<void>) | undefined;
  let onPublish: ((signal: AbortSignal | undefined) => Promise<void>) | undefined;
  let closeFailures = false;
  const signals: (AbortSignal | undefined)[] = [];
  const createDeployment: DurableObjectPublisherOptions["createDeployment"] = async ({
    identity,
  }) => {
    created++;
    expect(new TextDecoder().decode(identity)).toBe("private identity");
    complete = portableDeferred();
    ended = portableDeferred();
    const deployment: DurablePublisherDeployment = {
      async publish(
        nameOrHandler: string | FetchHandler,
        handlerOrOptions?: FetchHandler | TemporaryPublicationOptions,
        options?: NamedPublicationOptions,
      ): Promise<Publication> {
        const target = typeof nameOrHandler === "string" ? handlerOrOptions : nameOrHandler;
        if (typeof target !== "function") throw new Error("missing handler");
        handler = target;
        const selected = typeof nameOrHandler === "string" ? options : handlerOrOptions;
        const signal = typeof selected === "object" ? selected.signal : undefined;
        signals.push(signal);
        await onPublish?.(signal);
        if (failure !== undefined) throw failure;
        published++;
        const close = async () => {
          await onClose?.();
          if (closeFailures) throw new Error("private publication cleanup secret");
          complete.resolve();
        };
        return {
          url: "https://service.example",
          close,
          wait: () => complete.promise,
          [Symbol.asyncDispose]: close,
        };
      },
      async close() {
        closed++;
        if (closeFailures) throw new Error("private deployment cleanup secret");
        complete.resolve();
        ended.resolve();
      },
    };
    return deployment;
  };
  return {
    createDeployment,
    options: (text = "deployed handler"): DurableObjectPublisherOptions => ({
      configuration,
      identity: () => {
        identities++;
        return new TextEncoder().encode("private identity");
      },
      handler: () => () => new Response(text),
      createDeployment,
      restartIntervalMs: 1000,
    }),
    counts: () => ({ created, identities, published, closed }),
    handler: () => handler,
    signals,
    disconnect: () => {
      complete.reject(new Error("private runtime disconnected"));
      return ended.promise;
    },
    fail: (value: unknown) => {
      failure = value;
    },
    beforeClose: (value: () => Promise<void>) => {
      onClose = value;
    },
    beforePublish: (value: (signal: AbortSignal | undefined) => Promise<void>) => {
      onPublish = value;
    },
    failClose: (value = true) => {
      closeFailures = value;
    },
  };
}

test("new and stopped owners do not publish on construction or alarm", async () => {
  const fixture = sqlite();
  const engine = runtime();
  const owner = new DurableObjectPublisher(fixture.state, engine.options());
  await owner.ready;
  await owner.alarm();
  expect(engine.counts().created).toBe(0);
  expect(fixture.alarm()).toBeUndefined();
  await owner.stop();
  const restarted = new DurableObjectPublisher(fixture.state, engine.options());
  await restarted.ready;
  await restarted.alarm();
  expect(engine.counts().created).toBe(0);
});

test("the owner retains an injected publication after start returns", async () => {
  const fixture = sqlite();
  const engine = runtime();
  const owner = new DurableObjectPublisher(fixture.state, engine.options());
  const request = new AbortController();
  const initiate = async () => {
    await owner.start();
    return new Response("started");
  };
  await expect((await initiate()).text()).resolves.toBe("started");
  request.abort();
  await owner.resume();
  expect(engine.counts()).toEqual({ created: 1, identities: 1, published: 1, closed: 0 });
  expect(engine.signals[0]?.aborted).toBe(false);
  expect(fixture.alarm()).toEqual(expect.any(Number));
  const reply = await engine.handler()?.(new Request("https://service.example"));
  expect(await reply?.text()).toBe("deployed handler");
  await Promise.all(fixture.retained);
  expect(fixture.retained.size).toBe(0);
  await owner.stop();
  expect(engine.signals[0]?.aborted).toBe(true);
});

test("an alarm reconstructs code and a fresh runtime from durable intent and identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tnl-publisher-owner-"));
  directories.push(directory);
  const filename = join(directory, "publisher.sqlite");
  const firstState = sqlite(filename);
  const firstRuntime = runtime();
  const first = new DurableObjectPublisher(firstState.state, firstRuntime.options("old code"));
  await first.start();
  await firstRuntime.disconnect();
  const secondState = sqlite(filename);
  const secondRuntime = runtime();
  const second = new DurableObjectPublisher(
    secondState.state,
    secondRuntime.options("new deployed code"),
  );
  await second.ready;
  await second.alarm();
  expect(secondRuntime.counts()).toEqual({
    created: 1,
    identities: 0,
    published: 1,
    closed: 0,
  });
  const handler = secondRuntime.handler();
  expect(handler).toBeTypeOf("function");
  const reply = await handler?.(new Request("https://service.example"));
  expect(await reply?.text()).toBe("new deployed code");
  const rows = secondState.database
    .prepare("SELECT key FROM tnl_publisher_records_v1 ORDER BY key")
    .all();
  expect(rows).toEqual([
    { key: "7:default:@tnl/publisher-identity/v1" },
    { key: `7:default:${intentKey}` },
  ]);
  expect(JSON.stringify(second)).not.toContain("private identity");
  await second.stop();
  const thirdRuntime = runtime();
  const third = new DurableObjectPublisher(sqlite(filename).state, thirdRuntime.options());
  await third.ready;
  await third.alarm();
  expect(thirdRuntime.counts().created).toBe(0);
});

test("publication handle close persists stop before closing sockets", async () => {
  const fixture = sqlite();
  const engine = runtime();
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  engine.beforeClose(async () => {
    const bytes = await storage.get(intentKey);
    expect(JSON.parse(new TextDecoder().decode(bytes))).toMatchObject({ status: "stopped" });
  });
  const owner = new DurableObjectPublisher(fixture.state, engine.options());
  const publication = await owner.start();
  await publication.close();
  await publication.wait();
  await owner.alarm();
  expect(engine.counts().published).toBe(1);
  expect(fixture.alarm()).toBeUndefined();
});

test("publication wait joins terminal cleanup without exposing private runtime errors", async () => {
  const fixture = sqlite();
  const engine = runtime();
  const owner = new DurableObjectPublisher(fixture.state, engine.options());
  const publication = await owner.start();
  await engine.disconnect();
  await expect(publication.wait()).rejects.toMatchObject({
    code: "sdk.publication_failed",
    message: expect.not.stringContaining("private runtime disconnected"),
  });
  await expect(publication.wait()).rejects.not.toHaveProperty("cause");
  expect(engine.counts().closed).toBe(1);
  await owner.stop();
});

test("stop interrupts and joins pending publication after saving stopped intent", async () => {
  const fixture = sqlite();
  const engine = runtime();
  const entered = portableDeferred();
  engine.beforePublish(async (signal) => {
    entered.resolve();
    await new Promise<void>((_resolve, reject) => {
      signal?.addEventListener("abort", () => reject(new Error("private interrupted start")), {
        once: true,
      });
    });
  });
  const owner = new DurableObjectPublisher(fixture.state, engine.options());
  const starting = owner.start();
  void starting.catch(() => {});
  await entered.promise;
  expect(fixture.retained.size).toBeGreaterThan(0);
  await owner.stop();
  await expect(starting).rejects.toMatchObject({
    code: "sdk.publication_failed",
    message: expect.not.stringContaining("private interrupted start"),
  });
  expect(engine.counts().closed).toBe(1);
  const next = runtime();
  await new DurableObjectPublisher(fixture.state, next.options()).ready;
  expect(next.counts().created).toBe(0);
});

test("stop during a retained runtime's cleanup cannot allocate an uncanceled replacement", async () => {
  const fixture = sqlite();
  const engine = runtime();
  const owner = new DurableObjectPublisher(fixture.state, engine.options());
  await owner.start();
  engine.failClose();
  await expect(owner.stop()).rejects.toBeInstanceOf(AggregateError);
  engine.failClose(false);

  const cleanupEntered = portableDeferred();
  const finishCleanup = portableDeferred();
  engine.beforeClose(async () => {
    cleanupEntered.resolve();
    await finishCleanup.promise;
  });
  const replacementEntered = portableDeferred();
  const finishReplacement = portableDeferred();
  engine.beforePublish(async (signal) => {
    replacementEntered.resolve();
    const aborted = () => finishReplacement.resolve();
    signal?.addEventListener("abort", aborted, { once: true });
    try {
      await finishReplacement.promise;
    } finally {
      signal?.removeEventListener("abort", aborted);
    }
  });
  const restarting = owner.start();
  void restarting.catch(() => {});
  await cleanupEntered.promise;

  const stopSaved = portableDeferred();
  const deleteAlarm = fixture.state.storage.deleteAlarm;
  fixture.state.storage.deleteAlarm = async () => {
    await deleteAlarm();
    stopSaved.resolve();
  };
  const stopping = owner.stop();
  void stopping.catch(() => {});
  await stopSaved.promise;
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  expect(JSON.parse(new TextDecoder().decode(await storage.get(intentKey)))).toMatchObject({
    status: "stopped",
  });
  finishCleanup.resolve();

  const outcome = await Promise.race([
    stopping.then(() => "stopped"),
    replacementEntered.promise.then(() => "replacement"),
  ]);
  try {
    expect(outcome).toBe("stopped");
    await expect(restarting).rejects.toMatchObject({ name: "AbortError" });
    expect(engine.counts().created).toBe(1);
    await owner.alarm();
    expect(engine.counts().created).toBe(1);
  } finally {
    // an unfixed owner allocates a replacement with an un-aborted signal.
    // release the test worker explicitly so the regression fails without hanging.
    finishReplacement.resolve();
    await Promise.allSettled([restarting, stopping]);
    await Promise.all(fixture.retained);
  }
});

test("a startup failure keeps restart intent but never exposes private errors", async () => {
  const fixture = sqlite();
  const engine = runtime();
  engine.fail(new Error("private deployment credential"));
  const owner = new DurableObjectPublisher(fixture.state, engine.options());
  await expect(owner.start()).rejects.toMatchObject({
    code: "sdk.publication_failed",
    message: expect.not.stringContaining("private deployment credential"),
  });
  expect(engine.counts().closed).toBe(1);
  expect(fixture.alarm()).toEqual(expect.any(Number));
  const restartedRuntime = runtime();
  const restarted = new DurableObjectPublisher(fixture.state, restartedRuntime.options());
  await restarted.ready;
  expect(restartedRuntime.counts().published).toBe(1);
  await restarted.stop();
});

test("a stale alarm cannot republish after stop even if alarm deletion failed", async () => {
  const fixture = sqlite();
  const engine = runtime();
  const owner = new DurableObjectPublisher(fixture.state, engine.options());
  await owner.start();
  fixture.state.storage.deleteAlarm = async () => {
    throw new Error("private provider error");
  };
  await expect(owner.stop()).rejects.toMatchObject({
    code: "sdk.publisher_storage_unavailable",
  });
  const restartedRuntime = runtime();
  const restarted = new DurableObjectPublisher(fixture.state, restartedRuntime.options());
  await restarted.ready;
  await restarted.alarm();
  expect(restartedRuntime.counts().created).toBe(0);
});

test("independent cleanup failures remain visible without their private details", async () => {
  const fixture = sqlite();
  const engine = runtime();
  const owner = new DurableObjectPublisher(fixture.state, engine.options());
  await owner.start();
  engine.failClose();
  await expect(owner.stop()).rejects.toMatchObject({
    errors: [
      { code: "sdk.publication_cleanup_failed" },
      { code: "sdk.publication_cleanup_failed" },
    ],
  });
  const next = runtime();
  await new DurableObjectPublisher(fixture.state, next.options()).ready;
  expect(next.counts().created).toBe(0);
});

test("only whitelisted publication intent is serialized", async () => {
  const fixture = sqlite();
  const engine = runtime();
  const options = engine.options();
  const invalid = {
    ...options,
    configuration: { ...configuration, credential: "private credential" },
  };
  expect(() => new DurableObjectPublisher(fixture.state, invalid)).toThrow(
    expect.objectContaining({
      code: "sdk.configuration_invalid",
      message: expect.not.stringContaining("private credential"),
    }),
  );
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  await storage.put(
    intentKey,
    new TextEncoder().encode(
      JSON.stringify({
        version: 1,
        status: "running",
        configuration: invalid.configuration,
      }),
    ),
  );
  const owner = new DurableObjectPublisher(fixture.state, options);
  await expect(owner.ready).rejects.toMatchObject({
    code: "sdk.publisher_storage_invalid",
  });
  await expect(owner.alarm()).rejects.toMatchObject({
    code: "sdk.publisher_storage_invalid",
  });
  expect(engine.counts().created).toBe(0);
});
