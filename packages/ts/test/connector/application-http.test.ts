import { generateKeyPairSync, verify } from "node:crypto";
import { inspect } from "node:util";
import { afterEach, expect, test, vi } from "vitest";
import * as z from "zod";
import { createTnl, type TnlApplicationCredential, type TnlFetch } from "@tnldotdev/tnl/web";
import { createTnl as createNativeTnl } from "@tnldotdev/tnl";

const urlID = `url_${"U".repeat(22)}` as const;
const serviceID = `svc_${"S".repeat(22)}` as const;
const urlGrant = `pgrant_${"U".repeat(22)}`;
const serviceGrant = `pgrant_${"S".repeat(22)}`;
const token = `eyJhbGciOiJFZERTQSJ9.e30.${"A".repeat(86)}`;
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const publicBytes = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const credential: TnlApplicationCredential = {
    version: 1,
    control_url: "https://control.example",
    client_id: `pub_${"C".repeat(22)}`,
    key_id: `pkey_${"K".repeat(22)}`,
    team_id: "team",
    private_key: Buffer.concat([seed, publicBytes]).toString("base64url"),
    grants: [
      { id: urlGrant, operation: "visit", kind: "saved_public_url", public_url_id: urlID },
      { id: serviceGrant, operation: "visit", kind: "service", service_id: serviceID },
    ],
  };
  const state = {
    metadata: 1,
    protocol: "http",
    public: true,
    fault: "",
    control: 0,
    application: 0,
    nonces: new Set<string>(),
  };
  const record = (value: unknown) => z.record(z.string(), z.unknown()).parse(value);
  const dispatch = vi.fn<TnlFetch>(async (input, init) => {
    if (input instanceof Request) {
      state.application++;
      expect(input.headers.get("Tnl-Visitor-Token")).toBe(token);
      expect(init).toMatchObject({ redirect: "manual", credentials: "omit" });
      return new Response("application data");
    }
    state.control++;
    expect(init).toMatchObject({ method: "POST", redirect: "manual", credentials: "omit" });
    expect(new Headers(init?.headers).has("Authorization")).toBe(false);
    if (typeof init?.body !== "string") throw new Error("missing control body");
    const body = record(JSON.parse(init.body));
    if (String(input) === "https://control.example/v1/publisher-token") {
      expect(body).toMatchObject({
        grant_type: "client_credentials",
        client_id: credential.client_id,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      });
      if (typeof body.client_assertion !== "string") throw new Error("missing proof");
      const parts = body.client_assertion.split(".");
      const [header, payload, signature] = parts;
      if (header === undefined || payload === undefined || signature === undefined)
        throw new Error("invalid proof");
      expect(JSON.parse(Buffer.from(header, "base64url").toString())).toEqual({
        alg: "EdDSA",
        typ: "JWT",
        kid: credential.key_id,
      });
      const claims = record(JSON.parse(Buffer.from(payload, "base64url").toString()));
      expect(claims).toMatchObject({
        iss: credential.client_id,
        sub: credential.client_id,
        aud: "https://control.example/v1/publisher-token",
        grant_id: body.grant_id,
      });
      expect(typeof claims.jti).toBe("string");
      if (
        typeof claims.jti !== "string" ||
        typeof claims.iat !== "number" ||
        typeof claims.exp !== "number"
      )
        throw new Error("invalid claims");
      expect(claims.exp - claims.iat).toBe(60);
      expect(claims.jti).toMatch(/^[A-Za-z0-9_-]{32}$/);
      expect(state.nonces.has(claims.jti)).toBe(false);
      state.nonces.add(claims.jti);
      expect(
        verify(
          null,
          Buffer.from(`${header}.${payload}`),
          publicKey,
          Buffer.from(signature, "base64url"),
        ),
      ).toBe(true);
      if (state.fault === "denied") return new Response("private denial", { status: 403 });
      return Response.json({
        access_token: `pta_${"A".repeat(43)}`,
        token_type: "Bearer",
        expires_in: 300,
        grant_id: state.fault === "wrong grant" ? `pgrant_${"X".repeat(22)}` : body.grant_id,
      });
    }
    expect(String(input)).toBe("https://control.example/v1/visitor-tokens");
    expect(body.source).toEqual({ kind: "application", credential: `pta_${"A".repeat(43)}` });
    const resource = record(body.resource);
    const service = resource.kind === "service";
    return Response.json({
      resource:
        state.fault === "wrong resource"
          ? { kind: "service", id: `svc_${"X".repeat(22)}` }
          : resource,
      hostname: service ? "api.example" : "preview.example",
      port: service ? 10443 : 443,
      visitor_token: token,
      visitor_policy_revision: 1,
      expires_at: new Date(Date.now() + (state.fault === "expired" ? -1 : 300_000)).toISOString(),
      ...(service
        ? {
            service_protocol: state.protocol,
            service_endpoint: { hostname: "api.example", port: 10443, public: state.public },
            service_trust_revision: state.metadata,
          }
        : {}),
    });
  });
  vi.stubGlobal("fetch", dispatch);
  return { credential, state, dispatch };
}

test("application HTTP selects exact resource grants with Web Crypto and no native work", async () => {
  const { credential, state, dispatch } = fixture();
  const app = createTnl({ credential });
  expect(dispatch).not.toHaveBeenCalled();
  try {
    const api = await app.connect(urlID);
    expect(api.url).toBe("https://preview.example");
    await expect(
      (await api.fetch("/data", { headers: { Authorization: "Bearer application-owned" } })).text(),
    ).resolves.toBe("application data");
    const request = dispatch.mock.calls.find(([input]) => input instanceof Request)?.[0];
    expect(request).toBeInstanceOf(Request);
    if (!(request instanceof Request)) throw new Error("missing app request");
    expect(request.headers.get("Authorization")).toBe("Bearer application-owned");
    expect(request.url).toBe("https://preview.example/data");
    const service = await app.connect(serviceID);
    expect(service.url).toBe("https://api.example:10443");
    expect(state.control).toBe(4);
    expect(state.application).toBe(1);
  } finally {
    await app.close();
  }
});

test.each([
  ["web", (credential: string) => createTnl({ credential })],
  ["native", (credential: string) => createNativeTnl({ credential })],
] as const)(
  "%s accepts an environment JSON credential without changing its grants",
  async (_name, create) => {
    const { credential, state, dispatch } = fixture();
    const app = create(`\n${JSON.stringify(credential)}\n`);
    expect(dispatch).not.toHaveBeenCalled();
    try {
      const api = await app.connect(serviceID);
      expect(api.url).toBe("https://api.example:10443");
      expect(await (await api.fetch("/stock")).text()).toBe("application data");
      await expect(app.connect(`svc_${"X".repeat(22)}`)).rejects.toHaveProperty(
        "code",
        "sdk.credential_denied",
      );
      await expect(app.connect("https://personal.example")).rejects.toHaveProperty(
        "code",
        "sdk.credential_denied",
      );
      expect(state.control).toBe(2);
    } finally {
      await app.close();
    }
  },
);

test.each([createTnl, createNativeTnl])(
  "explicit invalid credential input cannot become personal authentication",
  (create) => {
    const { credential, dispatch } = fixture();
    for (const value of [
      undefined,
      null,
      "",
      [],
      {},
      `{"private_key":"${credential.private_key}"`,
      JSON.stringify({ ...credential, version: 2 }),
      JSON.stringify({ ...credential, workload: "deploy" }),
      `{${" ".repeat(128 * 1024)}}`,
    ]) {
      let error: unknown;
      try {
        Reflect.apply(create, undefined, [{ credential: value }]);
      } catch (cause) {
        error = cause;
      }
      expect(error).toHaveProperty("code");
      expect(inspect(error)).not.toContain(credential.private_key);
    }
    expect(dispatch).not.toHaveBeenCalled();
  },
);

test("application acquisition preserves expiration-independent A/B/A ordinary client reuse", async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  const { credential, state } = fixture();
  const app = createTnl({ credential });
  const create = vi.fn(() => ({ id: Symbol() }));
  const close = vi.fn();
  const get = app.client(serviceID, { create, close });
  try {
    const first = await get();
    vi.setSystemTime(Date.now() + 271_000);
    expect(await get()).toBe(first);
    expect(create).toHaveBeenCalledTimes(1);
    state.metadata = 2;
    vi.setSystemTime(Date.now() + 271_000);
    const second = await get();
    expect(second).not.toBe(first);
    state.metadata = 1;
    vi.setSystemTime(Date.now() + 271_000);
    expect(await get()).toBe(first);
    expect(create).toHaveBeenCalledTimes(2);
    expect(close).not.toHaveBeenCalled();
  } finally {
    await app.close();
  }
  expect(close).toHaveBeenCalledTimes(2);
});

test.each(["denied", "wrong grant", "wrong resource", "expired", "private", "database"])(
  "application %s authority never dispatches an app request or changes identity",
  async (fault) => {
    const { credential, state } = fixture();
    state.fault = fault;
    if (fault === "private") state.public = false;
    if (fault === "database") state.protocol = "postgres";
    const app = createTnl({ credential });
    try {
      await expect(app.connect(serviceID)).rejects.toHaveProperty(
        "code",
        fault === "wrong grant" || fault === "wrong resource"
          ? "sdk.credential_response_invalid"
          : fault === "database"
            ? "sdk.protocol_unsupported"
            : "sdk.credential_denied",
      );
      expect(state.application).toBe(0);
      expect(state.control).toBe(fault === "denied" || fault === "wrong grant" ? 1 : 2);
    } finally {
      await app.close();
    }
  },
);

test("application credentials reject ungranted resources and mismatched private-key halves before exchange", async () => {
  const { credential, state } = fixture();
  const app = createTnl({ credential });
  await expect(app.connect(`url_${"X".repeat(22)}`)).rejects.toHaveProperty(
    "code",
    "sdk.credential_denied",
  );
  await app.close();
  const privateBytes = Buffer.from(credential.private_key, "base64url");
  privateBytes[63] = (privateBytes[63] ?? 0) ^ 1;
  const invalid = createTnl({
    credential: { ...credential, private_key: privateBytes.toString("base64url") },
  });
  try {
    await expect(invalid.connect(urlID)).rejects.toHaveProperty("code", "sdk.credential_invalid");
  } finally {
    await invalid.close();
  }
  expect(state.control).toBe(0);
});

test("native instances use the same explicit application HTTP source without personal selection", async () => {
  const { credential, state } = fixture();
  expect(() => createNativeTnl({ credential, server: "https://another.example" })).toThrowError(
    expect.objectContaining({ code: "sdk.configuration_invalid" }),
  );
  const app = createNativeTnl({ credential });
  try {
    expect((await app.connect(urlID)).url).toBe("https://preview.example");
    // @ts-expect-error application documents cannot select project resources.
    await expect(app.connect("named-personal-service")).rejects.toHaveProperty(
      "code",
      "sdk.credential_denied",
    );
    await expect(app.publish(() => new Response("local"))).rejects.toHaveProperty(
      "code",
      "sdk.credential_denied",
    );
    expect(state.control).toBe(2);
  } finally {
    await app.close();
  }
});

test("application control errors retain private causes without exposing credentials", async () => {
  const { credential } = fixture();
  const cause = new Error(credential.private_key);
  vi.stubGlobal("fetch", vi.fn<TnlFetch>().mockRejectedValue(cause));
  const app = createTnl({ credential });
  try {
    const error: unknown = await app.connect(urlID).catch((cause: unknown) => cause);
    expect(error).toMatchObject({ code: "sdk.credential_unavailable", retry: "later" });
    expect(inspect(error, { showHidden: true, depth: 8 })).not.toContain(credential.private_key);
    expect(JSON.stringify(error)).not.toContain(credential.private_key);
  } finally {
    await app.close();
  }
});

test("canceling an upload during refresh releases its body without canceling another waiter", async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  const { credential, state, dispatch } = fixture();
  const app = createTnl({ credential });
  const gate = Promise.withResolvers<void>();
  const entered = Promise.withResolvers<void>();
  const abort = new AbortController();
  const reason = new Error("stop only this upload");
  const cancel = vi.fn();
  try {
    const api = await app.connect(urlID);
    vi.setSystemTime(Date.now() + 271_000);
    vi.stubGlobal(
      "fetch",
      vi.fn<TnlFetch>(async (input, init) => {
        if (String(input).endsWith("/v1/publisher-token")) {
          entered.resolve();
          await gate.promise;
          expect(init?.signal?.aborted).toBe(false);
        }
        return dispatch(input, init);
      }),
    );
    const body = new ReadableStream<Uint8Array>({ cancel });
    const upload = api
      .fetch("/upload", { method: "POST", body, signal: abort.signal })
      .catch((cause: unknown) => cause);
    await entered.promise;
    abort.abort(reason);
    expect(await upload).toBe(reason);
    expect(cancel).toHaveBeenCalledExactlyOnceWith(reason);
    expect(state.application).toBe(0);
    const other = api.fetch("/read");
    gate.resolve();
    expect(await (await other).text()).toBe("application data");
    expect(state.control).toBe(4);
    expect(state.application).toBe(1);
  } finally {
    gate.resolve();
    await app.close();
  }
});

test("scope cleanup aborts and joins authorization response cleanup without closing a sibling", async () => {
  const { credential, dispatch } = fixture();
  const app = createTnl({ credential });
  const sibling = createTnl({ credential });
  const entered = Promise.withResolvers<void>();
  const canceling = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  let signal: AbortSignal | null | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn<TnlFetch>(async (_input, init) => {
      signal = init?.signal;
      entered.resolve();
      return new Response(
        new ReadableStream<Uint8Array>({
          async cancel() {
            canceling.resolve();
            await release.promise;
          },
        }),
      );
    }),
  );
  const create = vi.fn(() => ({}));
  const get = app.client(urlID, { create, close: vi.fn() });
  const connecting = get().catch((cause: unknown) => cause);
  try {
    await entered.promise;
    let finished = false;
    const closing = app.close().then(() => {
      finished = true;
    });
    await canceling.promise;
    expect(signal?.aborted).toBe(true);
    expect(finished).toBe(false);
    expect(create).not.toHaveBeenCalled();
    release.resolve();
    await closing;
    expect(await connecting).toHaveProperty("code", "sdk.client_closed");
    await expect(get()).rejects.toHaveProperty("code", "sdk.client_closed");
    vi.stubGlobal("fetch", dispatch);
    expect((await sibling.connect(urlID)).url).toBe("https://preview.example");
  } finally {
    release.resolve();
    await Promise.all([app.close(), sibling.close()]);
  }
});

test.each(["proof", "permission"])(
  "malformed %s replies are bounded, private and never dispatch an app request",
  async (phase) => {
    for (const fault of ["json", "utf8", "oversized", "redirect", "unknown", "null", "token"]) {
      const { credential, state, dispatch } = fixture();
      const cancel = vi.fn();
      const app = createTnl({ credential });
      vi.stubGlobal(
        "fetch",
        vi.fn<TnlFetch>(async (input, init) => {
          const selected = String(input).endsWith(
            phase === "proof" ? "/v1/publisher-token" : "/v1/visitor-tokens",
          );
          if (!selected) return dispatch(input, init);
          if (fault === "json") return new Response(`{"private":"${credential.private_key}`);
          if (fault === "utf8") return new Response(new Uint8Array([255]));
          if (fault === "redirect")
            return new Response("private redirect", {
              status: 302,
              headers: { Location: "https://other.example" },
            });
          if (fault === "oversized")
            return new Response(
              new ReadableStream<Uint8Array>({
                start(controller) {
                  controller.enqueue(new Uint8Array(65537));
                },
                cancel,
              }),
            );
          const original = await dispatch(input, init);
          const value = z.record(z.string(), z.unknown()).parse(await original.json());
          if (fault === "unknown") value.private = credential.private_key;
          if (fault === "null") value.grant_id = null;
          if (fault === "token")
            value[phase === "proof" ? "access_token" : "visitor_token"] = "private\nheader";
          return Response.json(value);
        }),
      );
      try {
        const error: unknown = await app.connect(urlID).catch((cause: unknown) => cause);
        expect(error).toHaveProperty("code", "sdk.credential_response_invalid");
        expect(inspect(error, { showHidden: true, depth: 8 })).not.toContain(
          credential.private_key,
        );
        expect(state.application).toBe(0);
        if (fault === "oversized") expect(cancel).toHaveBeenCalledOnce();
      } finally {
        await app.close();
      }
    }
  },
);

test("refresh denial does not reuse expired authority or poison later exact acquisition", async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  const { credential, state } = fixture();
  const app = createTnl({ credential });
  const create = vi.fn((connection: { fetch: TnlFetch }) => connection);
  const get = app.client(serviceID, { create, close: vi.fn() });
  try {
    const first = await get();
    vi.setSystemTime(Date.now() + 301_000);
    expect(state.control).toBe(2);
    state.fault = "denied";
    await expect(first.fetch("/mutate", { method: "POST", body: "once" })).rejects.toHaveProperty(
      "code",
      "sdk.credential_denied",
    );
    await expect(get()).rejects.toHaveProperty("code", "sdk.credential_denied");
    expect(state.application).toBe(0);
    expect(create).toHaveBeenCalledOnce();
    state.fault = "";
    expect(await get()).toBe(first);
    state.metadata = 2;
    vi.setSystemTime(Date.now() + 271_000);
    await expect(first.fetch("/mutate", { method: "POST", body: "once" })).rejects.toHaveProperty(
      "code",
      "sdk.credential_denied",
    );
    expect(state.application).toBe(0);
    const second = await get();
    expect(second).not.toBe(first);
    expect(await (await second.fetch("/read")).text()).toBe("application data");
  } finally {
    await app.close();
  }
});

test("credential documents are copied and invalid grants never fall back to another operation", async () => {
  const { credential, state } = fixture();
  const app = createTnl({ credential });
  Reflect.set(credential.grants[0] ?? {}, "public_url_id", `url_${"X".repeat(22)}`);
  try {
    expect((await app.connect(urlID)).url).toBe("https://preview.example");
  } finally {
    await app.close();
  }
  const visit = credential.grants[0];
  if (visit === undefined || visit.kind !== "saved_public_url") throw new Error("missing grant");
  const publishOnly = createTnl({
    credential: {
      ...credential,
      grants: [{ ...visit, public_url_id: urlID, operation: "publish" }],
    },
  });
  try {
    await expect(publishOnly.connect(urlID)).rejects.toHaveProperty(
      "code",
      "sdk.credential_denied",
    );
  } finally {
    await publishOnly.close();
  }
  expect(state.control).toBe(2);
});
