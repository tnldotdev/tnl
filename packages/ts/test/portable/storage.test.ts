import { afterEach, expect, test, vi } from "vitest";
import { createBrowserPublisherStorage } from "../../src/internal/portable/storage-browser.js";
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

test("browser publishers refuse missing IndexedDB or cross-tab locking", () => {
  vi.stubGlobal("indexedDB", undefined);
  vi.stubGlobal("navigator", { locks: undefined });
  expect(() => createBrowserPublisherStorage()).toThrow(PublisherStorageError);
  vi.stubGlobal("indexedDB", {});
  expect(() => createBrowserPublisherStorage()).toThrow(PublisherStorageError);
});

test("SQLite replaces whole private records and returns independent bytes", async () => {
  const fixture = sqlite();
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  const original = new Uint8Array([1, 2, 3]);
  await storage.put("identity", original);
  original[0] = 9;
  const loaded = await storage.get("identity");
  expect(loaded).toEqual(new Uint8Array([1, 2, 3]));
  loaded?.fill(8);
  expect(await storage.get("identity")).toEqual(new Uint8Array([1, 2, 3]));
  await storage.put("identity", new Uint8Array([4, 5]));
  expect(await storage.get("identity")).toEqual(new Uint8Array([4, 5]));
  expect(JSON.stringify(storage)).toBe("{}");
  await storage.delete("identity");
  expect(await storage.get("identity")).toBeUndefined();
});

test("a failed SQLite replacement keeps the old atomic certificate record", async () => {
  const fixture = sqlite();
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  await storage.put("certificate", new Uint8Array([1, 2]));
  fixture.database.exec(
    "CREATE TRIGGER reject_update BEFORE UPDATE ON tnl_publisher_records_v1 BEGIN SELECT RAISE(ABORT, 'private signing key'); END",
  );
  await expect(storage.put("certificate", new Uint8Array([3, 4]))).rejects.toMatchObject({
    code: "sdk.publisher_storage_unavailable",
    message: expect.not.stringContaining("private signing key"),
  });
  expect(await storage.get("certificate")).toEqual(new Uint8Array([1, 2]));
});

test("SQLite storage namespaces keep owner identities and locks separate", async () => {
  const fixture = sqlite();
  const first = createDurableObjectPublisherStorage(fixture.state.storage, "first");
  const second = createDurableObjectPublisherStorage(fixture.state.storage, "second");
  await first.put("identity", new Uint8Array([1]));
  await second.put("identity", new Uint8Array([2]));
  expect(await first.get("identity")).toEqual(new Uint8Array([1]));
  expect(await second.get("identity")).toEqual(new Uint8Array([2]));
  await first.withLock("certificate", () => second.withLock("certificate", async () => {}));
});

test("attached-storage adapters share locks and an aborted waiter cannot unlock the holder", async () => {
  const fixture = sqlite();
  const first = createDurableObjectPublisherStorage(fixture.state.storage);
  const second = createDurableObjectPublisherStorage(fixture.state.storage);
  const entered = portableDeferred();
  const release = portableDeferred();
  const order: number[] = [];
  const held = first.withLock("certificate", async () => {
    order.push(1);
    entered.resolve();
    await release.promise;
    order.push(2);
  });
  await entered.promise;
  const controller = new AbortController();
  const canceled = second.withLock(
    "certificate",
    async () => {
      throw new Error("canceled waiter entered");
    },
    controller.signal,
  );
  controller.abort("private cancellation reason");
  await expect(canceled).rejects.toMatchObject({
    name: "AbortError",
    message: expect.not.stringContaining("private cancellation reason"),
  });
  const third = second.withLock("certificate", async () => {
    order.push(3);
  });
  expect(order).toEqual([1]);
  release.resolve();
  await Promise.all([held, third]);
  expect(order).toEqual([1, 2, 3]);
  await first.withLock("certificate", async () => {});
});

test("attached-storage corruption is explicit rather than a cache miss", async () => {
  const fixture = sqlite();
  const storage = createDurableObjectPublisherStorage(fixture.state.storage);
  fixture.database
    .prepare("INSERT INTO tnl_publisher_records_v1 (key, value) VALUES (?, ?)")
    .run("7:default:identity", "private invalid credential");
  await expect(storage.get("identity")).rejects.toMatchObject({
    code: "sdk.publisher_storage_invalid",
    message: expect.not.stringContaining("private invalid credential"),
  });
});

test("namespace and key separators cannot alias another owner's private records", async () => {
  const fixture = sqlite();
  const first = createDurableObjectPublisherStorage(fixture.state.storage, "first:second");
  const second = createDurableObjectPublisherStorage(fixture.state.storage, "first");
  await first.put("identity", new Uint8Array([1]));
  expect(await second.get("second:identity")).toBeUndefined();
  await second.put("second:identity", new Uint8Array([2]));
  expect(await first.get("identity")).toEqual(new Uint8Array([1]));
});
