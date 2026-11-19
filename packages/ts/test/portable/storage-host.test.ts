import { afterEach, expect, test } from "vitest";
import { createPublisherStorageHost } from "../../src/internal/portable/storage-host.js";
import { createDurableObjectPublisherStorage } from "../../src/internal/portable/storage-durable-object.js";
import { PublisherStorageError } from "../../src/internal/portable/storage.js";
import { portableDeferred, portableSQLite } from "../helpers/portable-sqlite.js";

const fixtures: ReturnType<typeof portableSQLite>[] = [];
afterEach(() => {
  for (const fixture of fixtures.splice(0)) fixture.close();
});
function sqlite() {
  const fixture = portableSQLite();
  fixtures.push(fixture);
  return fixture;
}
const scope = {
  control_url: "https://control.example",
  team_id: "team",
  publisher_identity_id: "publisher",
};
const scopeJSON = JSON.stringify(scope);
const signal = () => new AbortController().signal;

test("host records use canonical scope and bounded opaque byte values", async () => {
  const fixture = sqlite();
  const host = createPublisherStorageHost(
    createDurableObjectPublisherStorage(fixture.state.storage),
  );
  expect(await host.read(scopeJSON, "certificate", 10, signal())).toBeNull();
  await host.write(scopeJSON, "certificate", new Uint8Array([1, 2]), signal());
  await host.sync(scopeJSON, "certificate", signal());
  const reordered = JSON.stringify({
    publisher_identity_id: scope.publisher_identity_id,
    team_id: scope.team_id,
    control_url: scope.control_url,
  });
  expect(await host.read(reordered, "certificate", 2, signal())).toEqual(new Uint8Array([1, 2]));
  await expect(host.read(scopeJSON, "certificate", 1, signal())).rejects.toMatchObject({
    code: "sdk.publisher_storage_invalid",
  });
  for (const changed of [
    { ...scope, control_url: "https://other.example" },
    { ...scope, team_id: "other-team" },
    { ...scope, publisher_identity_id: "other-publisher" },
  ])
    expect(await host.read(JSON.stringify(changed), "certificate", 2, signal())).toBeNull();
  expect(JSON.stringify(host)).toBe("{}");
});

test("teamless scopes support private records and independent certificate locks", async () => {
  const fixture = sqlite();
  const host = createPublisherStorageHost(
    createDurableObjectPublisherStorage(fixture.state.storage),
  );
  const teamless = JSON.stringify({ ...scope, team_id: "" });
  await host.write(teamless, "certificate", new Uint8Array([1]), signal());
  expect(await host.read(teamless, "certificate", 1, signal())).toEqual(new Uint8Array([1]));
  expect(await host.read(scopeJSON, "certificate", 1, signal())).toBeNull();
  const releaseTeamless = await host.lock(teamless, "certificate", signal());
  const releaseTeam = await host.lock(scopeJSON, "certificate", signal());
  await releaseTeam();
  await releaseTeamless();
});

test.each([
  { ...scope, team_id: null },
  { ...scope, team_id: "x".repeat(4097) },
  { ...scope, team_id: "\0" },
  { ...scope, control_url: "" },
  { ...scope, publisher_identity_id: "" },
])("scope text remains bounded and only team_id may be empty %#", async (invalid) => {
  const fixture = sqlite();
  const host = createPublisherStorageHost(
    createDurableObjectPublisherStorage(fixture.state.storage),
  );
  await expect(
    host.read(JSON.stringify(invalid), "certificate", 1, signal()),
  ).rejects.toMatchObject({ code: "sdk.publisher_storage_invalid" });
});

test("host write resolves only after the record's durable sync completes", async () => {
  const fixture = sqlite();
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  const syncing = portableDeferred();
  const durable = portableDeferred();
  const events: string[] = [];
  let writtenKey: string | undefined;
  const host = createPublisherStorageHost({
    ...storage,
    async put(key, bytes) {
      await storage.put(key, bytes);
      writtenKey = key;
      events.push("put");
    },
    async sync(key) {
      expect(key).toBe(writtenKey);
      events.push("sync");
      syncing.resolve();
      await durable.promise;
      await storage.sync(key);
    },
  });
  const writing = host.write(scopeJSON, "certificate", new Uint8Array([1]), signal()).then(() => {
    events.push("resolved");
  });
  const outcome = await Promise.race([
    syncing.promise.then(() => "syncing"),
    writing.then(() => "resolved"),
  ]);
  try {
    expect(outcome).toBe("syncing");
    expect(events).toEqual(["put", "sync"]);
  } finally {
    durable.resolve();
    await writing;
  }
  expect(events).toEqual(["put", "sync", "resolved"]);
});

test("host write rejects a failed durable sync without exposing provider details", async () => {
  const fixture = sqlite();
  fixture.state.storage.sync = async () => {
    throw new Error("private durable storage failure");
  };
  const host = createPublisherStorageHost(
    createDurableObjectPublisherStorage(fixture.state.storage),
  );
  const writing = host.write(scopeJSON, "certificate", new Uint8Array([1]), signal());
  await expect(writing).rejects.toMatchObject({
    code: "sdk.publisher_storage_unavailable",
    message: expect.not.stringContaining("private durable storage failure"),
  });
  await expect(writing).rejects.not.toHaveProperty("cause");
});

test.each(["read", "write", "sync", "lock"] as const)(
  "host %s preserves an independent provider failure when cancellation races rejection",
  async (operation) => {
    const fixture = sqlite();
    const storage = createDurableObjectPublisherStorage(fixture.state.storage);
    const entered = portableDeferred();
    const fail = portableDeferred();
    const independentFailure = async (): Promise<never> => {
      entered.resolve();
      await fail.promise;
      throw new Error("private provider failure");
    };
    const host = createPublisherStorageHost({
      ...storage,
      ...(operation === "read" ? { get: independentFailure } : {}),
      ...(operation === "write" ? { put: independentFailure } : {}),
      ...(operation === "sync" ? { sync: independentFailure } : {}),
      ...(operation === "lock" ? { withLock: independentFailure } : {}),
    });
    const controller = new AbortController();
    const pending =
      operation === "read"
        ? host.read(scopeJSON, "certificate", 1, controller.signal)
        : operation === "write"
          ? host.write(scopeJSON, "certificate", new Uint8Array([1]), controller.signal)
          : operation === "sync"
            ? host.sync(scopeJSON, "certificate", controller.signal)
            : host.lock(scopeJSON, "certificate", controller.signal);
    void pending.catch(() => {});
    await entered.promise;
    controller.abort("private cancellation reason");
    fail.resolve();
    await expect(pending).rejects.toMatchObject({
      name: "AggregateError",
      errors: [{ code: "sdk.publisher_storage_unavailable" }, { name: "AbortError" }],
    });
    const error: unknown = await pending.catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(AggregateError);
    if (!(error instanceof AggregateError)) throw new Error("missing joined storage failure");
    expect(error.errors[0]).toBeInstanceOf(PublisherStorageError);
    expect(error.errors[0]).not.toHaveProperty("cause");
    const details = [error.message, JSON.stringify(error), ...error.errors.map(String)].join("\n");
    expect(details).not.toContain("private provider failure");
    expect(details).not.toContain("private cancellation reason");
  },
);

test.each(["success", "failure"] as const)(
  "a canceled write joins durable sync %s after its put completes",
  async (outcome) => {
    const fixture = sqlite();
    const storage = createDurableObjectPublisherStorage(fixture.state.storage);
    const putting = portableDeferred();
    const finishPut = portableDeferred();
    const syncing = portableDeferred();
    const finishSync = portableDeferred();
    const host = createPublisherStorageHost({
      ...storage,
      async put(key, bytes) {
        putting.resolve();
        await finishPut.promise;
        await storage.put(key, bytes);
      },
      async sync(key) {
        syncing.resolve();
        await finishSync.promise;
        if (outcome === "failure") throw new Error("private sync failure");
        await storage.sync(key);
      },
    });
    const controller = new AbortController();
    const writing = host.write(scopeJSON, "certificate", new Uint8Array([1]), controller.signal);
    void writing.catch(() => {});
    await putting.promise;
    controller.abort("private cancellation reason");
    finishPut.resolve();
    const pending = await Promise.race([
      syncing.promise.then(() => "syncing"),
      writing.then(
        () => "resolved",
        () => "rejected",
      ),
    ]);
    try {
      expect(pending).toBe("syncing");
    } finally {
      finishSync.resolve();
    }
    if (outcome === "success") {
      await expect(writing).rejects.toMatchObject({ name: "AbortError" });
    } else {
      await expect(writing).rejects.toMatchObject({
        name: "AggregateError",
        errors: [{ code: "sdk.publisher_storage_unavailable" }, { name: "AbortError" }],
      });
    }
  },
);

test("invalid returned record data remains an independent failure during cancellation", async () => {
  const fixture = sqlite();
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  const entered = portableDeferred();
  const finishRead = portableDeferred();
  const host = createPublisherStorageHost({
    ...storage,
    async get() {
      entered.resolve();
      await finishRead.promise;
      return new Uint8Array([1, 2]);
    },
  });
  const controller = new AbortController();
  const reading = host.read(scopeJSON, "certificate", 1, controller.signal);
  void reading.catch(() => {});
  await entered.promise;
  controller.abort();
  finishRead.resolve();
  await expect(reading).rejects.toMatchObject({
    name: "AggregateError",
    errors: [{ code: "sdk.publisher_storage_invalid" }, { name: "AbortError" }],
  });
});

test("host locks return idempotent async release functions and scope lock identity", async () => {
  const fixture = sqlite();
  const host = createPublisherStorageHost(
    createDurableObjectPublisherStorage(fixture.state.storage),
  );
  const first = await host.lock(scopeJSON, "certificate", signal());
  const second = host.lock(scopeJSON, "certificate", signal());
  const otherScope = await host.lock(
    JSON.stringify({ ...scope, publisher_identity_id: "other" }),
    "certificate",
    signal(),
  );
  await otherScope();
  await first();
  await first();
  const releaseSecond = await second;
  await releaseSecond();
  await (
    await host.lock(scopeJSON, "certificate", signal())
  )();
});

test("host lock abort joins its queue entry and acquired release ignores cancellation", async () => {
  const fixture = sqlite();
  const host = createPublisherStorageHost(
    createDurableObjectPublisherStorage(fixture.state.storage),
  );
  const owner = new AbortController();
  const release = await host.lock(scopeJSON, "certificate", owner.signal);
  const waiter = new AbortController();
  const waiting = host.lock(scopeJSON, "certificate", waiter.signal);
  void waiting.catch(() => {});
  waiter.abort("private abort reason");
  await expect(waiting).rejects.toMatchObject({
    name: "AbortError",
    message: expect.not.stringContaining("private abort reason"),
  });
  owner.abort();
  await release();
  await (
    await host.lock(scopeJSON, "certificate", signal())
  )();
});

test("host write joins underlying persistence even when cancellation races commit", async () => {
  const fixture = sqlite();
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  const entered = portableDeferred();
  const commit = portableDeferred();
  const host = createPublisherStorageHost({
    ...storage,
    async put(key, bytes) {
      entered.resolve();
      await commit.promise;
      await storage.put(key, bytes);
    },
  });
  const controller = new AbortController();
  const writing = host.write(scopeJSON, "identity", new Uint8Array([1]), controller.signal);
  void writing.catch(() => {});
  await entered.promise;
  controller.abort("private cancellation");
  commit.resolve();
  await expect(writing).rejects.toMatchObject({ name: "AbortError" });
  expect(await host.read(scopeJSON, "identity", 1, signal())).toEqual(new Uint8Array([1]));
});

test("host never exposes provider record errors or accepts credentials in scope", async () => {
  const fixture = sqlite();
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  const host = createPublisherStorageHost({
    ...storage,
    async get() {
      throw new Error("private credential material");
    },
  });
  const reading = host.read(scopeJSON, "identity", 100, signal());
  await expect(reading).rejects.toMatchObject({
    code: "sdk.publisher_storage_unavailable",
    message: expect.not.stringContaining("private credential material"),
  });
  await expect(reading).rejects.not.toHaveProperty("cause");
  await expect(
    host.read(JSON.stringify({ ...scope, credential: "private" }), "identity", 100, signal()),
  ).rejects.toMatchObject({ code: "sdk.publisher_storage_invalid" });
});
