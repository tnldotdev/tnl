import { readFileSync } from "node:fs";
import { expect, test } from "vitest";
import {
  browserFeedbackEventRequestSchema,
  browserFeedbackReportRequestSchema,
  feedbackThreadSchema,
} from "../../internal/publisher/browserapi/model.gen.ts";
import { batchSchema } from "../../pkg/api/integrations/telemetry/v1/model.gen.ts";

function fixture(path: string): unknown {
  return JSON.parse(
    readFileSync(new URL(`../../contracts/fixtures/${path}`, import.meta.url), "utf8"),
  );
}

test("generated validators preserve real Go fixtures as JSON, including numeric counters", () => {
  const thread = fixture("publisher/v1/thread.json");
  expect(feedbackThreadSchema.parse(thread)).toEqual(thread);
  expect(JSON.parse(JSON.stringify(feedbackThreadSchema.parse(thread)))).toEqual(thread);
  const batch = fixture("telemetry/v1/batch.json");
  expect(batchSchema.parse(batch)).toEqual(batch);
});

test("browser requests require their fields and cannot supply publisher-owned scope", () => {
  const report = browserFeedbackReportRequestSchema.parse(
    fixture("publisher/v1/report-request.json"),
  );
  expect(browserFeedbackReportRequestSchema.safeParse({ ...report, text: undefined }).success).toBe(
    false,
  );
  expect(
    browserFeedbackReportRequestSchema.safeParse({ ...report, preview_id: "other" }).success,
  ).toBe(false);
  expect(
    browserFeedbackEventRequestSchema.safeParse({ schema_version: 1, type: "reply" }).success,
  ).toBe(true);
  expect(
    browserFeedbackEventRequestSchema.safeParse({ schema_version: 1, type: "update" }).success,
  ).toBe(false);
});

test("telemetry rejects unknown data and mismatched event payloads at the receiver boundary", () => {
  const batch = batchSchema.parse(fixture("telemetry/v1/batch.json"));
  const first = batch.events[0];
  if (!first) throw new Error("telemetry fixture must contain an event");
  expect(batchSchema.safeParse({ ...batch, secret: "unexpected" }).success).toBe(false);
  expect(batchSchema.safeParse({ ...batch, schema_version: 2 }).success).toBe(false);
  for (const event of [
    { ...first.event, secret: "unexpected" },
    { ...first.event, event_version: 2 },
    { ...first.event, name: "publisher.report" },
    { ...first.event, payload: { ...first.event.payload, secret: "unexpected" } },
    { ...first.event, payload: { server_kind: "hosted", publish_mode: "app" } },
  ]) {
    expect(batchSchema.safeParse({ ...batch, events: [{ ...first, event }] }).success).toBe(false);
  }
});
