import { expect, test } from "vitest";
import { response } from "../../src/response.js";

test("response accepts another Response as its initializer", async () => {
  const initial = new Response(null, {
    status: 404,
    statusText: "Not Found",
    headers: { "X-Initial": "response" },
  });
  const result = response("replacement", initial);
  const copy = result.clone();
  expect([result.status, copy.status]).toEqual([404, 404]);
  expect([result.statusText, copy.statusText]).toEqual(["Not Found", "Not Found"]);
  expect([result.headers.get("X-Initial"), copy.headers.get("X-Initial")]).toEqual([
    "response",
    "response",
  ]);
  expect(await Promise.all([result.text(), copy.text()])).toEqual(["replacement", "replacement"]);
});

test("response reads inherited initializer getters once and ignores unmodeled properties", async () => {
  const reads = { headers: 0, status: 0, statusText: 0 };
  const initial: ResponseInit = Object.create({
    get headers() {
      reads.headers++;
      return { "X-Initial": "prototype" };
    },
    get status() {
      reads.status++;
      return 418;
    },
    get statusText() {
      reads.statusText++;
      return "Teapot";
    },
  });
  Object.defineProperty(initial, "ignored", {
    enumerable: true,
    get() {
      throw new Error("unmodeled initializer property must not be read");
    },
  });
  const result = response("replacement", initial);
  const copy = result.clone();
  expect(reads).toEqual({ headers: 1, status: 1, statusText: 1 });
  expect([result.status, copy.status]).toEqual([418, 418]);
  expect([result.statusText, copy.statusText]).toEqual(["Teapot", "Teapot"]);
  expect(result.headers.get("X-Initial")).toBe("prototype");
  expect(await Promise.all([result.text(), copy.text()])).toEqual(["replacement", "replacement"]);
});

test("undefined inherited initializer fields keep native Response defaults", async () => {
  const initial: ResponseInit = Object.create({
    get headers() {
      return undefined;
    },
    get status() {
      return undefined;
    },
    get statusText() {
      return undefined;
    },
  });
  const native = new Response("replacement", initial);
  const result = response("replacement", initial);
  expect(result.status).toBe(native.status);
  expect(result.statusText).toBe(native.statusText);
  expect(result.headers.get("Content-Type")).toBe(native.headers.get("Content-Type"));
  expect(await result.text()).toBe("replacement");
});
