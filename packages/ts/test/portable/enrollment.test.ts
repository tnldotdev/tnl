import { afterEach, expect, test, vi } from "vitest";
import { publish as publishService, publisher } from "../../src/browser.js";
import type { WasmBridge, WasmPublisherHost } from "../../src/internal/connector/wasm_abi.js";
import { createPublisherStorageHost } from "../../src/internal/portable/storage-host.js";
import type { PublisherStorage } from "../../src/internal/portable/storage.js";

const mocks = vi.hoisted(() => ({ load: vi.fn() }));
vi.mock("../../src/internal/connector/wasm_loader.js", () => ({ loadWasm: mocks.load }));

const deploymentID = `dpl_${"D".repeat(22)}`;
const publisherIdentityID = `pub_${"P".repeat(22)}`;
const controlUrl = "https://control.example.test";

function fixture() {
  const events: string[] = [];
  const live = Promise.withResolvers<void>();
  const exited = Promise.withResolvers<void>();
  const records = new Map<string, Uint8Array>();
  const publisherStorage: PublisherStorage = {
    async get(key) {
      return records.get(key);
    },
    async put(key, value) {
      records.set(key, value);
    },
    async delete(key) {
      records.delete(key);
    },
    async sync() {},
    async withLock(_name, operation) {
      return operation();
    },
  };
  const publish = vi.fn(async (_selection: string, _host: WasmPublisherHost) => ({
    public: true,
    url: "https://web.example.test",
    run: {
      serviceID: `svc_${"S".repeat(22)}`,
      serviceRunID: `srun_${"R".repeat(22)}`,
      runNumber: "1",
    },
    ready: Promise.resolve(),
    closed: live.promise,
    async close() {
      events.push("run:closing");
      await live.promise;
      events.push("run:joined");
    },
  }));
  const owner = {
    publisherIdentityID,
    deploymentID,
    publish,
    async close() {
      events.push("owner:close");
    },
  };
  const bridge = {
    enrollPublisher: vi.fn(
      async (
        _selection: string,
        _host: Parameters<NonNullable<WasmBridge["enrollPublisher"]>>[1],
      ) => owner,
    ),
    close: vi.fn(async () => {
      events.push("runtime:close");
      exited.resolve();
    }),
  };
  mocks.load.mockResolvedValue({ bridge, exited: exited.promise });
  return { events, live, publisherStorage, records, bridge, publish };
}

afterEach(() => {
  mocks.load.mockReset();
});

test("enrollment exposes named publication only and joins the run before releasing its identity", async () => {
  const f = fixture();
  const enrollment = vi.fn(() => "private-bootstrap");
  const enrolled = await publisher({
    controlUrl,
    publisherStorage: f.publisherStorage,
    enrollment,
  });
  expect(enrolled.publisherIdentityID).toBe(publisherIdentityID);
  expect(enrolled).not.toHaveProperty("connect");
  expect(enrollment).not.toHaveBeenCalled();
  const call = f.bridge.enrollPublisher.mock.calls[0];
  if (call === undefined) throw new Error("publisher bridge was not called");
  const [selection, host] = call;
  expect(JSON.parse(selection)).toEqual({ control_url: controlUrl, instance: "default" });
  expect(await host.enrollment?.()).toBe("private-bootstrap");
  expect(enrollment).toHaveBeenCalledOnce();
  await publishService(enrolled, "web", () => new Response("application"));
  expect(JSON.parse(f.publish.mock.calls[0]?.[0] ?? "")).toEqual({ service: "web" });
  const closing = enrolled.close();
  expect(enrolled.close()).toBe(closing);
  await vi.waitFor(() => expect(f.events).toEqual(["run:closing"]));
  await expect(enrolled.publish("web", () => new Response())).rejects.toMatchObject({
    code: "sdk.client_closed",
  });
  f.live.resolve();
  await closing;
  expect(f.events).toEqual(["run:closing", "run:joined", "owner:close", "runtime:close"]);
});

test("enrollment rejects malformed deployment handles and still joins their cleanup", async () => {
  const f = fixture();
  const bridge = f.bridge.enrollPublisher;
  bridge.mockImplementation(async () => ({
    publisherIdentityID,
    deploymentID: "malformed",
    publish: f.publish,
    async close() {
      f.events.push("owner:close");
    },
  }));
  await expect(
    publisher({ controlUrl, publisherStorage: f.publisherStorage }),
  ).rejects.toMatchObject({
    code: "sdk.wasm_invalid",
  });
  expect(f.events).toEqual(["owner:close", "runtime:close"]);
});

test("enrollment storage scopes cannot collide with certificate scopes", async () => {
  const f = fixture();
  const host = createPublisherStorageHost(f.publisherStorage);
  const signal = new AbortController().signal;
  const enrollment = JSON.stringify({ publisher_slot: "default" });
  const certificate = JSON.stringify({
    control_url: controlUrl,
    team_id: "team",
    publisher_identity_id: publisherIdentityID,
  });
  await host.write(enrollment, "identity.json", Uint8Array.of(1), signal);
  await host.write(certificate, "identity.json", Uint8Array.of(2), signal);
  expect(await host.read(enrollment, "identity.json", 32, signal)).toEqual(Uint8Array.of(1));
  expect(await host.read(certificate, "identity.json", 32, signal)).toEqual(Uint8Array.of(2));
  expect(f.records.size).toBe(2);
});
