import { expect, test, vi } from "vitest";
import { createFeedbackAPI } from "./api.ts";

test("malformed responses are errors, not a silently empty feedback list", async () => {
  const api = createFeedbackAPI(
    vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json({ threads: [{ id: "bad" }], event_cursor: 1 })),
  );
  await expect(api.list("/", undefined, new AbortController().signal)).rejects.toThrow(
    "invalid feedback",
  );
});

test("access and conflict errors have actionable text without leaking server response bodies", async () => {
  for (const [status, message] of [
    [403, "preview access expired"],
    [409, "feedback changed"],
  ] as const) {
    const api = createFeedbackAPI(
      vi
        .fn<typeof fetch>()
        .mockResolvedValue(new Response("private token in upstream response", { status })),
    );
    await expect(api.list("/", undefined, new AbortController().signal)).rejects.toThrow(message);
  }
});

test("browser mutations use same-origin cookies, an idempotency key, and an optional note", async () => {
  const id = "fb_0123456789abcdefghijkl";
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
    Response.json({
      cursor: 5,
      feedback_id: id,
      type: "thread.reopened",
      actor: "reviewer",
      at: "2026-10-05T00:00:00Z",
    }),
  );
  await createFeedbackAPI(fetcher).append(
    id,
    "thread.reopened",
    "",
    "retry-key",
    new AbortController().signal,
  );
  expect(fetcher).toHaveBeenCalledWith(
    "/__tnl/feedback/" + id + "/events",
    expect.objectContaining({
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "retry-key" },
      body: '{"type":"thread.reopened"}',
    }),
  );
});
