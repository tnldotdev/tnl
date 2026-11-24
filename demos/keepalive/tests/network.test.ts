import { afterEach, expect, it, vi } from "vitest";
import { HTTPFailure, request, requireStatus, retryOnce } from "../src/network.ts";

afterEach(() => vi.useRealTimers());

it("honors a short Retry-After, then tries once", async () => {
  vi.useFakeTimers();
  const send = vi
    .fn<typeof fetch>()
    .mockResolvedValueOnce(new Response(null, { status: 429, headers: { "Retry-After": "1" } }))
    .mockResolvedValueOnce(new Response(null, { status: 200 }));
  vi.stubGlobal("fetch", send);
  const { signal } = new AbortController();
  const result = retryOnce(signal, async () => requireStatus(await request("/read", { signal })));
  await vi.advanceTimersByTimeAsync(999);
  expect(send).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(400);
  expect(send).toHaveBeenCalledTimes(2);
  await expect(result).resolves.toHaveProperty("status", 200);
});

it("cancels a scheduled retry before sending another request", async () => {
  vi.useFakeTimers();
  const send = vi.fn<typeof fetch>().mockRejectedValue(new TypeError("lost connection"));
  vi.stubGlobal("fetch", send);
  const owner = new AbortController();
  const checked = expect(
    retryOnce(owner.signal, () => request("/read", { signal: owner.signal })),
  ).rejects.toMatchObject({ name: "AbortError" });
  await vi.advanceTimersByTimeAsync(100);
  owner.abort();
  await checked;
  await vi.runAllTimersAsync();
  expect(send).toHaveBeenCalledOnce();
});

it.each([new HTTPFailure(403), new HTTPFailure(429, "120"), new SyntaxError("invalid body")])(
  "does not retry a terminal response",
  async (failure) => {
    const run = vi.fn().mockRejectedValue(failure);
    await expect(retryOnce(new AbortController().signal, run)).rejects.toBe(failure);
    expect(run).toHaveBeenCalledOnce();
  },
);
