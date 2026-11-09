import { expect, test, vi } from "vitest";
import { publicationHandle } from "../../src/internal/publisher/publication.js";
import type { RuntimeEndpoint } from "../../src/internal/publisher/local.js";

const registrationID = `reg_${"a".repeat(32)}`;
const target = "http://127.0.0.1:3000";
const endpoint: RuntimeEndpoint = {
  version: 1,
  url: "http://127.0.0.1:1234",
  owner_id: "a".repeat(32),
  capability: "b".repeat(64),
  scope: "app",
  service: "web",
};
type Request = NonNullable<Parameters<typeof publicationHandle>[0]["request"]>;
function snapshot(checkedAt?: string) {
  return {
    schema_version: 1,
    project: "/project",
    cursor: "initial",
    observed_at: new Date().toISOString(),
    services: [
      {
        service: "web",
        directory: ".",
        tunnel_id: "tunnel",
        registration_id: registrationID,
        target,
        registered: true,
        routable: true,
        ready: checkedAt !== undefined,
        run_number: 2,
        readiness: { path: "/ready" },
        ...(checkedAt === undefined
          ? {}
          : {
              observation: {
                registration_id: registrationID,
                run_number: 2,
                checked_at: checkedAt,
                ready: true,
                readiness: { path: "/ready" },
              },
            }),
      },
    ],
  };
}
function fixture(request: Request) {
  const lifetime = new AbortController();
  const done = Promise.withResolvers<void>();
  const close = vi.fn(async () => {
    lifetime.abort(new Error("closed"));
    done.resolve();
  });
  const handle = publicationHandle({
    current: () => ({ endpoint, service: "web", registrationID, target }),
    url: () => "https://web.example",
    lifetime: lifetime.signal,
    close,
    finished: () => done.promise,
    request,
  });
  return { handle, close, lifetime };
}

test("status does not probe; wait performs a fresh native readiness check", async () => {
  const request = vi.fn<Request>(async (_endpoint, operation) =>
    snapshot(operation === "check" ? new Date().toISOString() : undefined),
  );
  const { handle } = fixture(request);
  expect(await handle.status()).toMatchObject({
    routable: true,
    ready: false,
    publishRunNumber: 2,
    tunnelID: "tunnel",
  });
  await handle.wait({ until: "routable" });
  expect(request.mock.calls.map(([, operation]) => operation)).toEqual(["status", "status"]);
  await handle.wait();
  expect(request.mock.calls.at(-1)?.slice(1, 3)).toEqual(["check", { services: ["web"] }]);
});

test("cancelling observation does not stop publication or change its finished promise", async () => {
  const { handle, close } = fixture(async () => snapshot());
  const abort = new AbortController();
  const reason = new Error("stop observing");
  const waiting = handle.wait({ signal: abort.signal });
  const rejected = expect(waiting).rejects.toBe(reason);
  abort.abort(reason);
  await rejected;
  expect(close).not.toHaveBeenCalled();
  let finished = false;
  const done = handle.finished().then(() => {
    finished = true;
  });
  await handle.status();
  expect(finished).toBe(false);
  await handle.close();
  await done;
  expect(finished).toBe(true);
});

test("watch starts from a native snapshot and resumes exclusive event cursors", async () => {
  const request = vi.fn<Request>(async (_endpoint, operation) =>
    operation === "status"
      ? snapshot()
      : [{ cursor: "next", type: "cursor", at: new Date().toISOString() }],
  );
  const { handle } = fixture(request);
  const stream = handle.watch()[Symbol.asyncIterator]();
  expect((await stream.next()).value).toMatchObject({ type: "snapshot", cursor: "initial" });
  expect((await stream.next()).value).toMatchObject({ type: "cursor", cursor: "next" });
  expect(request.mock.calls.at(-1)?.slice(1, 3)).toEqual(["events", { after: "initial" }]);
  await stream.return?.();
  const resumed = handle.watch({ after: "saved" })[Symbol.asyncIterator]();
  expect((await resumed.next()).value).toMatchObject({ cursor: "next" });
  expect(request.mock.calls.at(-1)?.slice(1, 3)).toEqual(["events", { after: "saved" }]);
  await resumed.return?.();
});

test("watch rejects cross-service payloads and retains cursor-expiry errors", async () => {
  const error = new Error("cursor expired");
  let fail = false;
  const { handle } = fixture(async (_endpoint, operation) => {
    if (operation === "status") return snapshot();
    if (fail) throw error;
    return [
      {
        cursor: "next",
        type: "snapshot",
        at: new Date().toISOString(),
        snapshot: { ...snapshot(), services: [{ ...snapshot().services[0], service: "sibling" }] },
      },
    ];
  });
  await expect(
    handle.watch({ after: "saved" })[Symbol.asyncIterator]().next(),
  ).rejects.toHaveProperty("code", "sdk.response_invalid");
  fail = true;
  await expect(handle.watch({ after: "saved" })[Symbol.asyncIterator]().next()).rejects.toBe(error);
});

test("an in-flight status reply cannot cross native owner replacement", async () => {
  const current = { endpoint, service: "web", registrationID, target };
  const request = vi.fn<Request>(async () => {
    current.registrationID = `reg_${"b".repeat(32)}`;
    return snapshot();
  });
  const handle = publicationHandle({
    current: () => ({ ...current }),
    url: () => undefined,
    lifetime: new AbortController().signal,
    close: async () => {},
    finished: async () => {},
    request,
  });
  await expect(handle.status()).rejects.toHaveProperty("code", "sdk.registration_stale");
});

test("finished rejects terminal native publication failure without replaying application work", async () => {
  const state = snapshot();
  const { handle } = fixture(async () => ({
    ...state,
    services: state.services.map((service) => ({
      ...service,
      failure: "runtime.publication_failed",
    })),
  }));
  await expect(handle.finished()).rejects.toHaveProperty("code", "sdk.publication_failed");
});
