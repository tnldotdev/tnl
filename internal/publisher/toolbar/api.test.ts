import { expect, test, vi } from "vitest";
import { readFileSync } from "node:fs";
import { createFeedbackAPI } from "./api.ts";
import { reportInputSchema } from "./model.ts";
import {
  browserAccessStatusSchema,
  feedbackThreadSchema,
  feedbackEventSchema,
} from "../browserapi/model.gen.ts";

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(
      new URL(`../../../contracts/fixtures/publisher/v1/${name}.json`, import.meta.url),
      "utf8",
    ),
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

test("access and conflict errors have actionable text without leaking server response bodies", async () => {
  for (const [status, message] of [
    [401, "sign in to write feedback"],
    [403, "do not have permission"],
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
      cursor: "5",
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
  const wire = feedbackThreadSchema.parse(fixture("thread"));
  const event = feedbackEventSchema.parse(fixture("event"));
  const input = reportInputSchema.parse(fixture("report-request"));
  expect(reportInputSchema.safeParse({ ...input, display_name: "unverified" }).success).toBe(false);
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json(wire));
  const api = createFeedbackAPI(fetcher);
  const thread = await api.report(input, "fixture-report", new AbortController().signal);
  expect(thread.report.text).toBe(input.text);
  expect(thread.scope.page_path).toBe(input.page_path);
  expect(thread.report.author?.display_name).toBe("Sam");
  expect(wire.scope).toMatchObject({
    service_id: "svc_0123456789abcdefghijkl",
    service_run_id: "srun_0123456789abcdefghijkl",
    run_number: "2",
  });
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
  ).toMatchObject({ cursor: "5", type: "reply" });
});

test("browser access binds the exact service run without publication compatibility fields", () => {
  const status = {
    schema_version: 1,
    allowed: true,
    preview_id: "pv_0123456789abcdefghijkl",
    service_id: "svc_0123456789abcdefghijkl",
    service_run_id: "srun_0123456789abcdefghijkl",
    run_number: "2",
    access_method: "share",
  };
  expect(browserAccessStatusSchema.parse(status)).toEqual(status);
  expect(
    browserAccessStatusSchema.safeParse({
      schema_version: status.schema_version,
      allowed: status.allowed,
      preview_id: status.preview_id,
      public_url_id: "url_0123456789abcdefghijkl",
      publish_run_number: "2",
    }).success,
  ).toBe(false);
});

test("browser report input cannot select service scope, run, or source state", () => {
  const input = reportInputSchema.parse(fixture("report-request"));
  for (const forged of [
    { service_id: "svc_0123456789abcdefghijkl" },
    { service_run_id: "srun_0123456789abcdefghijkl" },
    { run_number: "99" },
    { source_at_report: { complete: true } },
  ]) {
    expect(reportInputSchema.safeParse({ ...input, ...forged }).success).toBe(false);
  }
});
