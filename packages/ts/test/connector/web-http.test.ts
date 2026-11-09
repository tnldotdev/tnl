import { inspect } from "node:util";
import { build } from "esbuild";
import { afterEach, expect, test, vi } from "vitest";
import { createTnl, type TnlFetch, type TnlHTTPConnection } from "@tnldotdev/tnl/web";
import { createTnl as createNativeTnl } from "@tnldotdev/tnl";

const credential = `vsh1.shr_${"A".repeat(22)}.${"A".repeat(43)}`;
const otherCredential = `vsg1.shg_${"B".repeat(22)}.${"A".repeat(43)}`;
afterEach(() => vi.unstubAllGlobals());

test("web HTTP preserves application data and never forwards credentials across redirects", async () => {
  const dispatch = vi.fn<TnlFetch>(async (input, init) => {
    if (!(input instanceof Request)) throw new Error("expected Request");
    expect(input.url).toBe("https://app.example/upload");
    expect(input.headers.get("Tnl-Visitor-Token")).toBe(credential);
    expect(input.headers.get("Authorization")).toBe("Bearer application-owned");
    expect(input.headers.get("Cookie")).toBe("app=unchanged");
    expect(input.method).toBe("POST");
    expect(await input.text()).toBe("streamed body");
    expect(init).toMatchObject({ redirect: "manual", credentials: "omit" });
    return new Response("not replayed", {
      status: 302,
      headers: { location: "https://other.example/" },
    });
  });
  vi.stubGlobal("fetch", dispatch);
  const app = createTnl({ credential });
  const api = await app.connect("https://app.example");
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("streamed body"));
      controller.close();
    },
  });
  const response = await api.fetch("/upload", {
    method: "POST",
    body,
    redirect: "follow",
    headers: { Authorization: "Bearer application-owned", Cookie: "app=unchanged" },
  });
  expect(response.status).toBe(302);
  expect(await response.text()).toBe("not replayed");
  await expect(api.fetch("https://other.example/")).rejects.toHaveProperty(
    "code",
    "sdk.configuration_invalid",
  );
  await expect(
    api.fetch("/", { headers: { "Tnl-Visitor-Token": otherCredential } }),
  ).rejects.toHaveProperty("code", "sdk.configuration_invalid");
  expect(dispatch).toHaveBeenCalledOnce();
  await app.close();
});

test("HTTP denial and network failure never fall back or replay a request", async () => {
  const dispatch = vi
    .fn<TnlFetch>()
    .mockResolvedValueOnce(new Response("denied", { status: 403 }))
    .mockRejectedValueOnce(new Error(`private provider details: ${credential}`));
  vi.stubGlobal("fetch", dispatch);
  const app = createTnl({ credential });
  const api = app.connect("https://app.example");
  expect((await api.fetch("/mutate", { method: "POST", body: "once" })).status).toBe(403);
  expect(dispatch).toHaveBeenCalledOnce();
  const error: unknown = await api.fetch("/").catch((cause: unknown) => cause);
  expect(error).toMatchObject({
    code: "sdk.http_unavailable",
    class: "unavailable",
    retry: "later",
  });
  expect(inspect(error)).not.toContain(credential);
  expect(inspect(error)).not.toContain("private provider details");
  expect(dispatch).toHaveBeenCalledTimes(2);
  await app.close();
});

test("web clients reuse the existing factory and retry failed cleanup", async () => {
  const app = createTnl({ credential });
  const failure = new Error("driver close failed");
  const close = vi.fn().mockRejectedValueOnce(failure).mockResolvedValue(undefined);
  const create = vi.fn((connection: TnlHTTPConnection) => ({ fetch: connection.fetch }));
  const get = app.client("https://app.example", { create, close });
  const [first, second] = await Promise.all([get(), get()]);
  expect(first).toBe(second);
  expect(create).toHaveBeenCalledOnce();
  await expect(app.close()).rejects.toMatchObject({ errors: [failure] });
  await expect(get()).rejects.toHaveProperty("code", "sdk.client_closed");
  await app.close();
  expect(close).toHaveBeenCalledTimes(2);
});

test("web cleanup joins late client creation and closes its value", async () => {
  const gate = Promise.withResolvers<void>();
  const started = Promise.withResolvers<void>();
  const app = createTnl({ credential });
  const value = {};
  const close = vi.fn();
  const get = app.client("https://app.example", {
    async create() {
      started.resolve();
      await gate.promise;
      return value;
    },
    close,
  });
  const creating = get().catch((cause: unknown) => cause);
  await started.promise;
  let completed = false;
  const closing = app.close().then(() => {
    completed = true;
  });
  await Promise.resolve();
  expect(completed).toBe(false);
  gate.resolve();
  expect(await creating).toHaveProperty("code", "sdk.client_closed");
  await closing;
  expect(close).toHaveBeenCalledExactlyOnceWith(value);
});

test("closing one HTTP scope cancels its fetches without affecting another", async () => {
  const entered = Promise.withResolvers<void>();
  let stopped: AbortSignal | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn<TnlFetch>(async (input, init) => {
      if (!(input instanceof Request)) throw new Error("expected Request");
      if (input.headers.get("Tnl-Visitor-Token") === otherCredential)
        return new Response("sibling");
      stopped = init?.signal ?? undefined;
      entered.resolve();
      return new Promise<Response>((_resolve, reject) =>
        stopped?.addEventListener("abort", () => reject(stopped?.reason), { once: true }),
      );
    }),
  );
  const a = createTnl({ credential });
  const b = createTnl({ credential: otherCredential });
  const pending = a
    .connect("https://app.example")
    .fetch("/hang")
    .catch((cause: unknown) => cause);
  await entered.promise;
  await a.close();
  expect(await pending).toHaveProperty("code", "sdk.client_closed");
  expect(stopped?.aborted).toBe(true);
  expect(await (await b.connect("https://service.example:25443").fetch("/")).text()).toBe(
    "sibling",
  );
  await b.close();
});

test("request cancellation retains its reason without closing the HTTP scope", async () => {
  const reason = new Error("stop this request");
  const controller = new AbortController();
  const dispatch = vi.fn<TnlFetch>(async () => new Response("ok"));
  vi.stubGlobal("fetch", dispatch);
  const app = createTnl({ credential });
  const api = app.connect("https://app.example");
  controller.abort(reason);
  await expect(api.fetch("/", { signal: controller.signal })).rejects.toBe(reason);
  expect(dispatch).not.toHaveBeenCalled();
  expect(await (await api.fetch("/")).text()).toBe("ok");
  await app.close();
});

test.each(["cross-origin", "conflicting header", "aborted"])(
  "an undispatched %s request releases its upload",
  async (fault) => {
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({ cancel });
    const abort = new AbortController();
    if (fault === "aborted") abort.abort();
    const dispatch = vi.fn<TnlFetch>();
    vi.stubGlobal("fetch", dispatch);
    const app = createTnl({ credential });
    try {
      await expect(
        app
          .connect("https://app.example")
          .fetch(fault === "cross-origin" ? "https://other.example/upload" : "/upload", {
            method: "POST",
            body,
            signal: abort.signal,
            ...(fault === "conflicting header"
              ? { headers: { "Tnl-Visitor-Token": credential } }
              : {}),
          }),
      ).rejects.toThrow();
      expect(cancel).toHaveBeenCalledOnce();
      expect(dispatch).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  },
);

test("invalid credentials and resource paths fail without exposing private values", async () => {
  for (const invalid of [
    "",
    `${credential}=`,
    credential.slice(0, -1) + "B",
    "private value",
    `vsh1.invalid.${"A".repeat(43)}`,
  ]) {
    let error: unknown;
    try {
      createTnl({ credential: invalid });
    } catch (cause) {
      error = cause;
    }
    expect(error).toHaveProperty("code", "sdk.configuration_invalid");
    if (invalid !== "") expect(inspect(error)).not.toContain(invalid);
  }
  const app = createTnl({ credential });
  expect(() => app.connect("https://app.example/path")).toThrow(
    expect.objectContaining({ code: "sdk.configuration_invalid" }),
  );
  await app.close();
});

test("the web entry bundles without native or Node dependencies", async () => {
  const result = await build({
    entryPoints: ["packages/ts/dist/web.js"],
    platform: "browser",
    format: "esm",
    bundle: true,
    write: false,
    metafile: true,
    logLevel: "silent",
  });
  expect(
    Object.keys(result.metafile.inputs).some((filename) =>
      /native|connection_bridge|publisher|node_modules\/.+undici/.test(filename),
    ),
  ).toBe(false);
  expect(Object.values(result.metafile.outputs).flatMap((output) => output.imports)).toEqual([]);
  expect(result.outputFiles[0]?.text).not.toMatch(/\b(?:require\(|process\.|Buffer\.)/);
});

test("native instances use the same explicit HTTP credential without personal publisher fallback", async () => {
  const dispatch = vi.fn<TnlFetch>(async (input) => {
    if (!(input instanceof Request)) throw new Error("expected Request");
    expect(input.headers.get("Tnl-Visitor-Token")).toBe(credential);
    return new Response("explicit");
  });
  vi.stubGlobal("fetch", dispatch);
  const app = createNativeTnl({ credential });
  expect(await (await app.connect("https://app.example").fetch("/")).text()).toBe("explicit");
  // @ts-expect-error explicit tokens cannot select project resources.
  expect(() => app.connect("database")).toThrow(
    expect.objectContaining({ code: "sdk.credential_denied" }),
  );
  await expect(app.prepare()).rejects.toHaveProperty("code", "sdk.credential_denied");
  await expect(app.publish(() => new Response("app"))).rejects.toHaveProperty(
    "code",
    "sdk.credential_denied",
  );
  expect(dispatch).toHaveBeenCalledOnce();
  await app.close();
});
