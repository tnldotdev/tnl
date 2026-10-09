import { expect, test, vi } from "vitest";
import { readFileSync } from "node:fs";
import { createFeedbackAPI } from "./api.ts";
import { reportInputSchema } from "./model.ts";
import {
  FeedbackThread as WireThread,
  FeedbackEvent as WireEvent,
} from "../publisherapi/model.gen.ts";

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(new URL(`../../api/fixtures/publisher/v1/${name}.json`, import.meta.url), "utf8"),
  );
}

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

test("oversized response streams are canceled before buffering the whole body", async () => {
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(new Uint8Array(1 << 19));
    },
    cancel,
  });
  await expect(
    createFeedbackAPI(async () => new Response(body)).access(new AbortController().signal),
  ).rejects.toMatchObject({ code: "response_invalid" });
  expect(cancel).toHaveBeenCalledOnce();
});

test("generated policy and browser-session validators reject missing, null, old and contradictory identity data", async () => {
  const signal = new AbortController().signal;
  const anonymous = {
    require_sign_in: false,
    sign_in_available: false,
    identity_state: "anonymous",
  };
  for (const value of [
    {},
    { ...anonymous, require_sign_in: null },
    { ...anonymous, sign_in_available: "yes" },
    { ...anonymous, identity_state: "signed_in" },
    { ...anonymous, identity: { identity_id: "sam", display_name: "Sam" } },
    { ...anonymous, identity_state: "signed_in", identity: { display_name: "Sam" } },
    { ...anonymous, extra: true },
  ]) {
    await expect(
      createFeedbackAPI(async () => Response.json(value)).access(signal),
    ).rejects.toMatchObject({ code: "response_invalid" });
  }
  for (const required of [true, false]) {
    expect(
      await createFeedbackAPI(async () =>
        Response.json({ ...anonymous, require_sign_in: required }),
      ).access(signal),
    ).toMatchObject({ require_sign_in: required });
  }
  for (const value of [
    {},
    { signed_in: null },
    { signed_in: true },
    { signed_in: true, display_name: "Sam", team_member: false },
    { signed_in: false, display_name: "Sam" },
  ]) {
    await expect(
      createFeedbackAPI(async () => Response.json(value)).session(signal),
    ).rejects.toMatchObject({ code: "response_invalid" });
  }
  const fetcher = vi
    .fn<typeof fetch>()
    .mockResolvedValue(
      Response.json({ signed_in: true, display_name: "Sam", visit_allowed: false }),
    );
  expect(await createFeedbackAPI(fetcher).session(signal)).toMatchObject({
    signed_in: true,
    visit_allowed: false,
  });
  expect(fetcher).toHaveBeenCalledWith(
    "/__tnl/team/session",
    expect.objectContaining({ credentials: "same-origin", cache: "no-store" }),
  );
});

test("sign-in required, denied access and availability remain distinct and safe", async () => {
  for (const [status, code] of [
    [401, "sign_in_required"],
    [403, "access_expired"],
    [503, "unavailable"],
  ] as const) {
    await expect(
      createFeedbackAPI(async () => new Response("private-provider-secret", { status })).access(
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code });
  }
});

test("access and conflict errors have actionable text without leaking server response bodies", async () => {
  for (const [status, message] of [
    [403, "preview access was denied"],
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
      schema_version: 1,
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
      body: '{"schema_version":1,"type":"thread.reopened"}',
    }),
  );
});

test("shared Go wire fixtures produce a readable report and a bounded browser submission", async () => {
  const wire = WireThread.parse(fixture("thread"));
  const event = WireEvent.parse(fixture("event"));
  const input = reportInputSchema.parse(fixture("report-request"));
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json(wire));
  const api = createFeedbackAPI(fetcher);
  const thread = await api.report(input, "fixture-report", new AbortController().signal);
  expect(thread.report.text).toBe(input.text);
  expect(thread.scope.page_path).toBe(input.page_path);
  expect(thread.report.author?.display_name).toBe("Sam");
  expect(fetcher).toHaveBeenCalledWith(
    "/__tnl/feedback",
    expect.objectContaining({
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "fixture-report" },
      body: JSON.stringify(input),
    }),
  );
  fetcher.mockResolvedValueOnce(Response.json(event));
  expect(
    await api.append(
      wire.id,
      "reply",
      event.text ?? "",
      "fixture-reply",
      new AbortController().signal,
    ),
  ).toMatchObject({ cursor: 5, type: "reply" });
});
