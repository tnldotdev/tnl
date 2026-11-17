import { createServer } from "node:http";
import { build } from "esbuild";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright";
import { afterAll, afterEach, beforeAll, beforeEach, expect, test } from "vitest";
import type * as storage from "../../src/internal/portable/storage-browser.js";
import type * as requests from "../../src/internal/portable/request.js";
import type * as responses from "../../src/response.js";
import type { PublisherStorage } from "../../src/internal/portable/storage.js";

declare global {
  interface Window {
    portablePublisher: typeof storage & typeof requests & typeof responses;
    publisherStorage: PublisherStorage & { close(): Promise<void> };
    releasePublisherLock: () => void;
    publisherWork: Promise<void>;
    publisherEntered: boolean;
    publisherResult: number[];
  }
}

let browser: Browser;
let context: BrowserContext;
let origin: string;
let source: string;
const server = createServer((_request, reply) => {
  reply
    .writeHead(200, { "Content-Type": "text/html" })
    .end("<!doctype html><title>publisher</title>");
});

beforeAll(async () => {
  const bundle = await build({
    stdin: {
      contents: [
        'export * from "./packages/ts/src/internal/portable/storage-browser.ts";',
        'export * from "./packages/ts/src/internal/portable/request.ts";',
        'export * from "./packages/ts/src/response.ts";',
      ].join("\n"),
      resolveDir: process.cwd(),
      loader: "ts",
    },
    bundle: true,
    write: false,
    format: "iife",
    globalName: "portablePublisher",
    platform: "browser",
  });
  source = bundle.outputFiles[0]?.text ?? "";
  expect(source).not.toBe("");
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("missing test listener");
  origin = `http://127.0.0.1:${address.port}`;
  browser = await chromium.launch({ channel: "chrome" });
});

beforeEach(async () => {
  context = await browser.newContext();
});
afterEach(async () => {
  await context.close();
});
afterAll(async () => {
  await browser?.close();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
});

async function page(): Promise<Page> {
  const result = await context.newPage();
  await result.goto(origin);
  await result.addScriptTag({ content: source });
  return result;
}

test("IndexedDB keeps complete private records across tabs and storage reopen", async () => {
  const first = await page();
  const second = await page();
  await first.evaluate(async () => {
    const store = window.portablePublisher.createBrowserPublisherStorage();
    const record = new Uint8Array([1, 2, 3]);
    await store.put("identity", record);
    record.fill(9);
    await store.close();
  });
  expect(
    await second.evaluate(async () => {
      const store = window.portablePublisher.createBrowserPublisherStorage();
      const loaded = await store.get("identity");
      const original = Array.from(loaded ?? []);
      loaded?.fill(8);
      const again = Array.from((await store.get("identity")) ?? []);
      await store.put("identity", new Uint8Array([4, 5]));
      await store.close();
      return { original, again };
    }),
  ).toEqual({ original: [1, 2, 3], again: [1, 2, 3] });
  expect(
    await first.evaluate(async () => {
      const store = window.portablePublisher.createBrowserPublisherStorage();
      const record = Array.from((await store.get("identity")) ?? []);
      await store.delete("identity");
      const absent = (await store.get("identity")) === undefined;
      await store.close();
      return { record, absent };
    }),
  ).toEqual({ record: [4, 5], absent: true });
});

test("Web Locks prevent duplicate identity preparation across real Chrome tabs", async () => {
  const first = await page();
  const second = await page();
  await first.evaluate(() => {
    window.publisherStorage = window.portablePublisher.createBrowserPublisherStorage();
    window.publisherEntered = false;
    window.publisherWork = window.publisherStorage.withLock("identity", async () => {
      window.publisherEntered = true;
      if ((await window.publisherStorage.get("identity")) !== undefined)
        throw new Error("expected fresh identity");
      await new Promise<void>((resolve) => {
        window.releasePublisherLock = resolve;
      });
      await window.publisherStorage.put("identity", new Uint8Array([1, 2]));
    });
  });
  await first.waitForFunction(() => window.publisherEntered);
  await second.evaluate(() => {
    window.publisherStorage = window.portablePublisher.createBrowserPublisherStorage();
    window.publisherEntered = false;
    window.publisherWork = window.publisherStorage.withLock("identity", async () => {
      window.publisherEntered = true;
      const existing = await window.publisherStorage.get("identity");
      window.publisherResult = Array.from(existing ?? []);
      if (existing === undefined) throw new Error("duplicate identity preparation");
    });
  });
  await second.waitForFunction(async () => {
    const locks = await navigator.locks.query();
    return locks.pending?.length === 1;
  });
  expect(await second.evaluate(() => window.publisherEntered)).toBe(false);
  await first.evaluate(async () => {
    window.releasePublisherLock();
    await window.publisherWork;
  });
  await second.evaluate(() => window.publisherWork);
  expect(await second.evaluate(() => window.publisherResult)).toEqual([1, 2]);
});

test("IndexedDB put waits for commit, not request success, and preserves the old record on abort", async () => {
  const tab = await page();
  expect(
    await tab.evaluate(async () => {
      let abortWrites = false;
      let requestSucceeded = false;
      const open = indexedDB.open.bind(indexedDB);
      const factory: IDBFactory = Object.create(indexedDB);
      factory.open = (name, version) => {
        const request = open(name, version);
        request.addEventListener("success", () => {
          const db = request.result;
          const transaction = db.transaction.bind(db);
          Object.defineProperty(db, "transaction", {
            value: (
              stores: string | string[],
              mode?: IDBTransactionMode,
              options?: IDBTransactionOptions,
            ) => {
              const tx = transaction(stores, mode, options);
              if (mode === "readwrite" && abortWrites) {
                const objectStore = tx.objectStore.bind(tx);
                Object.defineProperty(tx, "objectStore", {
                  value: (storeName: string) => {
                    const store = objectStore(storeName);
                    const put = store.put.bind(store);
                    Object.defineProperty(store, "put", {
                      value: (value: unknown, key?: IDBValidKey) => {
                        const writing = put(value, key);
                        writing.addEventListener("success", () => {
                          requestSucceeded = true;
                          tx.abort();
                        });
                        return writing;
                      },
                    });
                    return store;
                  },
                });
              }
              return tx;
            },
          });
        });
        return request;
      };
      const store = window.portablePublisher.createBrowserPublisherStorage({
        indexedDB: factory,
      });
      await store.put("certificate", new Uint8Array([1, 2]));
      abortWrites = true;
      let failure: unknown;
      try {
        await store.put("certificate", new Uint8Array([3, 4]));
      } catch (error) {
        failure = error instanceof Error && "code" in error ? error.code : "wrong error";
      }
      const record = Array.from((await store.get("certificate")) ?? []);
      await store.close();
      return { requestSucceeded, failure, record };
    }),
  ).toEqual({
    requestSucceeded: true,
    failure: "sdk.publisher_storage_unavailable",
    record: [1, 2],
  });
});

test("publisher storage never silently replaces unavailable safe primitives", async () => {
  const tab = await page();
  expect(
    await tab.evaluate(() => {
      Object.defineProperty(navigator, "locks", { value: undefined });
      try {
        window.portablePublisher.createBrowserPublisherStorage();
        return "unexpected fallback";
      } catch (error) {
        return error instanceof Error && "code" in error ? error.code : "wrong error";
      }
    }),
  ).toBe("sdk.publisher_storage_unavailable");
});

test("Request clones keep Go-attached Cookie headers and tee the genuine body", async () => {
  const tab = await page();
  expect(
    await tab.evaluate(async () => {
      const nativeClone = Request.prototype.clone;
      const raw = new Headers([
        ["Cookie", "visitor=credential; preference=compact"],
        ["X-Example", "value"],
      ]);
      const request = new Request("https://service.example/upload", {
        method: "POST",
        headers: raw,
        body: "streamed request",
      });
      const plainCookie = request.headers.get("Cookie");
      // this is exactly the Go bridge's own-headers attachment.
      Object.defineProperty(request, "headers", { value: raw });
      const wrapped = window.portablePublisher.preserveRequestHeaders(request);
      const copy = wrapped.clone();
      const secondCopy = copy.clone();
      const beforeMutation = copy.headers.get("X-Example");
      raw.set("X-Example", "changed");
      const bodies = await Promise.all([wrapped.text(), copy.text(), secondCopy.text()]);
      let usedCloneRejected = false;
      try {
        wrapped.clone();
      } catch (error) {
        usedCloneRejected = error instanceof TypeError;
      }
      return {
        plainCookie,
        cookies: [wrapped, copy, secondCopy].map((value) => value.headers.get("Cookie")),
        genuine: [wrapped, copy, secondCopy].every((value) => value instanceof Request),
        unchangedPrototype: Request.prototype.clone === nativeClone,
        beforeMutation,
        cloneUnaffected: copy.headers.get("X-Example"),
        bodies,
        usedCloneRejected,
      };
    }),
  ).toEqual({
    plainCookie: null,
    cookies: Array(3).fill("visitor=credential; preference=compact"),
    genuine: true,
    unchangedPrototype: true,
    beforeMutation: "value",
    cloneUnaffected: "value",
    bodies: Array(3).fill("streamed request"),
    usedCloneRejected: true,
  });
});

test("response opts into raw Set-Cookie headers on genuine responses and repeated clones", async () => {
  const tab = await page();
  expect(
    await tab.evaluate(async () => {
      const nativeClone = Response.prototype.clone;
      const headers: [string, string][] = [
        ["Set-Cookie", "first=one; HttpOnly; Secure; SameSite=Lax"],
        ["Set-Cookie", "second=two; Path=/; Secure"],
      ];
      const plain = new Response("plain browser response", { headers });
      const original = window.portablePublisher.response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("streamed "));
            controller.enqueue(new TextEncoder().encode("response"));
            controller.close();
          },
        }),
        { status: 201, headers },
      );
      const copy = original.clone();
      const secondCopy = copy.clone();
      original.headers.append("Set-Cookie", "third=three; Secure");
      const cookies = [original, copy, secondCopy].map((value) => value.headers.getSetCookie());
      const bodies = await Promise.all([original.text(), copy.text(), secondCopy.text()]);
      let usedCloneRejected = false;
      try {
        original.clone();
      } catch (error) {
        usedCloneRejected = error instanceof TypeError;
      }
      return {
        plain: plain.headers.getSetCookie(),
        cookies,
        genuine: [original, copy, secondCopy].every((value) => value instanceof Response),
        statuses: [original, copy, secondCopy].map((value) => value.status),
        unchangedPrototype: Response.prototype.clone === nativeClone,
        bodies,
        usedCloneRejected,
      };
    }),
  ).toEqual({
    plain: [],
    cookies: [
      [
        "first=one; HttpOnly; Secure; SameSite=Lax",
        "second=two; Path=/; Secure",
        "third=three; Secure",
      ],
      ["first=one; HttpOnly; Secure; SameSite=Lax", "second=two; Path=/; Secure"],
      ["first=one; HttpOnly; Secure; SameSite=Lax", "second=two; Path=/; Secure"],
    ],
    genuine: true,
    statuses: [201, 201, 201],
    unchangedPrototype: true,
    bodies: Array(3).fill("streamed response"),
    usedCloneRejected: true,
  });
});

test("response preserves the generated FormData boundary with raw cookies and repeated clones", async () => {
  const tab = await page();
  const result = await tab.evaluate(async () => {
    const form = new FormData();
    form.set("example", "portable");
    form.set("file", new File(["hello file"], "note.txt", { type: "text/plain" }));
    const original = window.portablePublisher.response(form, {
      headers: [["Set-Cookie", "visitor=credential; HttpOnly; Secure"]],
    });
    const copy = original.clone();
    const secondCopy = copy.clone();
    const type = original.headers.get("Content-Type");
    const boundary = type?.match(/boundary=(?:"([^"]+)"|([^;]+))/);
    const delimiter = boundary?.[1] ?? boundary?.[2];
    const [body, copiedBody, parsed] = await Promise.all([
      original.text(),
      copy.text(),
      secondCopy.formData(),
    ]);
    const file = parsed.get("file");
    return {
      types: [original, copy, secondCopy].map((value) => value.headers.get("Content-Type")),
      cookies: [original, copy, secondCopy].map((value) => value.headers.getSetCookie()),
      matchingBodies: body === copiedBody,
      boundaryMatchesBody:
        delimiter !== undefined &&
        body.startsWith(`--${delimiter}\r\n`) &&
        body.includes(`\r\n--${delimiter}--`),
      field: parsed.get("example"),
      fileName: file instanceof File ? file.name : null,
      fileBody: file instanceof File ? await file.text() : null,
    };
  });
  expect(result.types).toEqual(
    Array(3).fill(expect.stringMatching(/^multipart\/form-data; boundary=.+$/)),
  );
  expect(new Set(result.types).size).toBe(1);
  expect(result).toMatchObject({
    cookies: Array(3).fill(["visitor=credential; HttpOnly; Secure"]),
    matchingBodies: true,
    boundaryMatchesBody: true,
    field: "portable",
    fileName: "note.txt",
    fileBody: "hello file",
  });
});

test.each([
  ["string", "text/plain;charset=UTF-8", "string body"],
  ["blob", "application/example", "blob body"],
  ["url-search-params", "application/x-www-form-urlencoded;charset=UTF-8", "example=portable"],
] as const)(
  "response keeps generated %s Content-Type and later raw header mutations through clones",
  async (kind, contentType, bodyText) => {
    const tab = await page();
    expect(
      await tab.evaluate(async (bodyKind) => {
        const body =
          bodyKind === "string"
            ? "string body"
            : bodyKind === "blob"
              ? new Blob(["blob body"], { type: "application/example" })
              : new URLSearchParams({ example: "portable" });
        const original = window.portablePublisher.response(body, {
          headers: [["Set-Cookie", "first=one; Secure"]],
        });
        const copy = original.clone();
        copy.headers.set("Content-Type", "application/custom");
        copy.headers.append("Set-Cookie", "second=two; Secure");
        const secondCopy = copy.clone();
        const generatedType = original.headers.get("Content-Type");
        original.headers.delete("Content-Type");
        const withoutType = original.clone();
        const bodies = await Promise.all(
          [original, copy, secondCopy, withoutType].map((value) => value.text()),
        );
        return {
          generatedType,
          cloneTypes: [copy, secondCopy].map((value) => value.headers.get("Content-Type")),
          deletedType: withoutType.headers.get("Content-Type"),
          cookies: [original, copy, secondCopy, withoutType].map((value) =>
            value.headers.getSetCookie(),
          ),
          bodies,
        };
      }, kind),
    ).toEqual({
      generatedType: contentType,
      cloneTypes: ["application/custom", "application/custom"],
      deletedType: null,
      cookies: [
        ["first=one; Secure"],
        ["first=one; Secure", "second=two; Secure"],
        ["first=one; Secure", "second=two; Secure"],
        ["first=one; Secure"],
      ],
      bodies: Array(4).fill(bodyText),
    });
  },
);

test.each(["response", "prototype", "undefined"] as const)(
  "response reads the %s initializer through the native ResponseInit fields",
  async (kind) => {
    const tab = await page();
    const result = await tab.evaluate(async (initializerKind) => {
      const reads = { headers: 0, status: 0, statusText: 0 };
      const initial: ResponseInit =
        initializerKind === "response"
          ? new Response(null, {
              status: 404,
              statusText: "Not Found",
              headers: { "X-Initial": "response" },
            })
          : Object.create({
              get headers() {
                reads.headers++;
                return initializerKind === "undefined" ? undefined : { "X-Initial": "prototype" };
              },
              get status() {
                reads.status++;
                return initializerKind === "undefined" ? undefined : 418;
              },
              get statusText() {
                reads.statusText++;
                return initializerKind === "undefined" ? undefined : "Teapot";
              },
            });
      if (initializerKind !== "response")
        Object.defineProperty(initial, "ignored", {
          enumerable: true,
          get() {
            throw new Error("unmodeled initializer property must not be read");
          },
        });
      const original = window.portablePublisher.response("replacement", initial);
      const copy = original.clone();
      const secondCopy = copy.clone();
      const values = [original, copy, secondCopy];
      return {
        statuses: values.map((value) => value.status),
        statusTexts: values.map((value) => value.statusText),
        headers: values.map((value) => value.headers.get("X-Initial")),
        contentTypes: values.map((value) => value.headers.get("Content-Type")),
        bodies: await Promise.all(values.map((value) => value.text())),
        reads,
      };
    }, kind);
    expect(result).toEqual({
      statuses: Array(3).fill(kind === "response" ? 404 : kind === "prototype" ? 418 : 200),
      statusTexts: Array(3).fill(
        kind === "response" ? "Not Found" : kind === "prototype" ? "Teapot" : "",
      ),
      headers: Array(3).fill(kind === "undefined" ? null : kind),
      contentTypes: Array(3).fill("text/plain;charset=UTF-8"),
      bodies: Array(3).fill("replacement"),
      reads:
        kind === "response"
          ? { headers: 0, status: 0, statusText: 0 }
          : { headers: 1, status: 1, statusText: 1 },
    });
  },
);
