import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import * as path from "node:path";
import { expect, test } from "vitest";
import { TnlError } from "./src/errors.js";
import { openServer, parseAdHocStatus } from "./src/internal/open.js";
import type { NodeHTTPServer } from "./src/internal/register.js";

const listener: NodeHTTPServer = {
  listening: true,
  address: () => ({ address: "127.0.0.1", port: 3000 }),
  once: () => listener,
  off: () => listener,
  close: () => listener,
};

const credential = () =>
  `tnl_eph_${randomBytes(16).toString("base64url")}.${randomBytes(32).toString("base64url")}`;

test("the ad-hoc Go, TypeScript, and Python socket fixture has the same bounded status", async () => {
  const fixturePath = path.resolve(
    import.meta.dirname,
    "../../internal/privateprotocol/testdata/adhoc.json",
  );
  const fixture: unknown = JSON.parse(await readFile(fixturePath, "utf8"));
  if (
    fixture === null ||
    typeof fixture !== "object" ||
    !("ready" in fixture) ||
    !("failed" in fixture)
  )
    throw new Error("invalid ad-hoc fixture");
  const ready = fixture.ready;
  if (
    ready === null ||
    typeof ready !== "object" ||
    !("registration_id" in ready) ||
    typeof ready.registration_id !== "string"
  )
    throw new Error("invalid ready fixture");
  const id = ready.registration_id;
  const status = parseAdHocStatus(ready, id);
  expect(status.state).toBe("routable");
  expect(status.publicURL).toBe("https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test");
  expect(status.publishRunNumber).toBe(1);
  expect(() => parseAdHocStatus({ ...ready, credential: "secret" }, id)).toThrow(TnlError);
  expect(parseAdHocStatus(fixture.failed, id).failureCode).toBe("runtime.publication_failed");
});

test("one supplied Node listener waits for its run and stays open on close", async () => {
  const calls: string[] = [];
  let registrationID = "";
  let statuses = 0;
  const handle = await openServer(
    listener,
    { credential: credential(), targetHostname: "app.internal" },
    {
      start: async () => "/tmp/tnl-test.sock",
      request: async (_socket, operation, body: unknown) => {
        calls.push(operation);
        if (
          body === null ||
          typeof body !== "object" ||
          !("registration_id" in body) ||
          typeof body.registration_id !== "string"
        )
          throw new Error("invalid private request");
        registrationID ||= body.registration_id;
        expect(body.registration_id).toBe(registrationID);
        if (operation === "ad-hoc/register") {
          expect(body).toHaveProperty("target", "http://app.internal:3000");
        }
        if (operation === "ad-hoc/unregister" || operation === "ad-hoc/renew") return undefined;
        const status = {
          version: 1,
          registration_id: registrationID,
          ...(operation === "ad-hoc/register"
            ? { state: "starting" }
            : ++statuses === 1
              ? {
                  state: "publishing",
                  public_url_id: "url_allocated",
                  public_url: "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test",
                }
              : {
                  state: "routable",
                  public_url_id: "url_allocated",
                  public_url: "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test",
                  publish_run_number: 2,
                }),
        };
        return status;
      },
      pause: async () => new Promise((resolve) => setTimeout(resolve, 1)),
    },
  );
  expect(handle.url).toBe("https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test");
  expect(calls.filter((call) => call === "ad-hoc/status")).toHaveLength(2);
  await handle.close();
  await handle.wait();
  expect(listener.listening).toBe(true);
  expect(calls.at(-1)).toBe("ad-hoc/unregister");
});

test("a strict total budget fails closed when the native manager disappears", async () => {
  let starts = 0;
  await expect(
    openServer(
      listener,
      { credential: credential(), limits: { requests: 1 } },
      {
        start: async () => {
          starts++;
          return "/tmp/tnl-test.sock";
        },
        request: async (_socket, operation, body: unknown) => {
          if (operation === "ad-hoc/status") throw new TnlError("sdk.dev_unavailable");
          if (operation === "ad-hoc/unregister") return undefined;
          if (body === null || typeof body !== "object" || !("registration_id" in body))
            throw new Error("invalid private request");
          return { version: 1, registration_id: body.registration_id, state: "starting" };
        },
        pause: async () => new Promise((resolve) => setTimeout(resolve, 1)),
      },
    ),
  ).rejects.toMatchObject({ code: "sdk.registration_stale" });
  expect(starts).toBe(1);
});

test("an unlimited handle reuses its invocation after a native manager restart", async () => {
  let starts = 0;
  const ids: string[] = [];
  let lost = false;
  const handle = await openServer(
    listener,
    { credential: credential() },
    {
      start: async () => {
        starts++;
        return `/tmp/tnl-test-${starts}.sock`;
      },
      request: async (_socket, operation, body: unknown) => {
        if (operation === "ad-hoc/unregister" || operation === "ad-hoc/renew") return undefined;
        if (
          body === null ||
          typeof body !== "object" ||
          !("registration_id" in body) ||
          typeof body.registration_id !== "string"
        )
          throw new Error("invalid private request");
        if (operation === "ad-hoc/register") {
          ids.push(body.registration_id);
          return starts === 1
            ? { version: 1, registration_id: body.registration_id, state: "starting" }
            : {
                version: 1,
                registration_id: body.registration_id,
                state: "routable",
                public_url_id: "url_same",
                public_url: "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test",
                publish_run_number: 2,
              };
        }
        if (!lost) {
          lost = true;
          throw new TnlError("sdk.dev_unavailable");
        }
        throw new Error("unexpected status request");
      },
      pause: async () => new Promise((resolve) => setTimeout(resolve, 1)),
    },
  );
  expect(starts).toBe(2);
  expect(ids).toHaveLength(2);
  expect(ids[0]).toBe(ids[1]);
  expect(handle.url).toBe("https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test");
  await handle.close();
});

test("an authored native credential denial becomes a typed SDK error", async () => {
  await expect(
    openServer(
      listener,
      { credential: credential() },
      {
        start: async () => "/tmp/tnl-test.sock",
        request: async (_socket, operation, body: unknown) => {
          if (operation === "ad-hoc/unregister") return undefined;
          if (body === null || typeof body !== "object" || !("registration_id" in body))
            throw new Error("invalid private request");
          return {
            version: 1,
            registration_id: body.registration_id,
            state: "failed",
            failure_code: "runtime.credential_rejected",
          };
        },
        pause: async () => new Promise((resolve) => setTimeout(resolve, 1)),
      },
    ),
  ).rejects.toMatchObject({ code: "sdk.credential_rejected" });
});
