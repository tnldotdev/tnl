import { z } from "zod";
import { BrowserFeedbackEventRequest, BrowserFeedbackEvidence } from "../publisherapi/model.gen.ts";
import {
  evidenceSchema,
  eventPageSchema,
  eventSchema,
  reportInputSchema,
  threadPageSchema,
  threadSchema,
  type BrowserEvent,
  type Evidence,
  type EventPage,
  type FeedbackEvent,
  type ReportInput,
  type Thread,
  type ThreadPage,
} from "./model.ts";

/** same-origin publisher API; wire contract: api/publisher/v1/openapi.yaml. */
export interface FeedbackAPI {
  /** hostname-scoped summaries; path omission selects all pages, cursor is a feedback ID. */
  list(
    path: string | undefined,
    cursor: string | undefined,
    signal: AbortSignal,
    state?: "open" | "resolved",
  ): Promise<ThreadPage>;
  /** immutable report and current state, scoped to this public URL and preview. */
  inspect(id: string, signal: AbortSignal): Promise<Thread>;
  /** ordered events after a numeric cursor; follow next_cursor until caught up. */
  events(id: string, cursor: number | undefined, signal: AbortSignal): Promise<EventPage>;
  /** bounded, browser-scoped failures; query strings and request bodies are omitted. */
  evidence(signal: AbortSignal): Promise<Evidence["failed_requests"]>;
  /** first submission; retries must reuse the same key and frozen input. */
  report(input: ReportInput, key: string, signal: AbortSignal): Promise<Thread>;
  /** replies require text; resolve/reopen accept an optional note and the same retry key. */
  append(
    id: string,
    type: BrowserEvent,
    text: string,
    key: string,
    signal: AbortSignal,
  ): Promise<FeedbackEvent>;
}

export function createFeedbackAPI(fetcher: typeof fetch = fetch): FeedbackAPI {
  async function request<T>(
    path: string,
    schema: z.ZodType<T>,
    signal: AbortSignal,
    body?: unknown,
    key?: string,
  ): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (key) headers["Idempotency-Key"] = key;
    const response = await fetcher("/__tnl/feedback" + path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      signal,
      headers,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      if (response.status === 403)
        throw new Error("preview access expired; reopen your share link");
      if (response.status === 409) throw new Error("feedback changed; refresh and try again");
      throw new Error("could not save or load feedback; try again");
    }
    const value: unknown = await response.json();
    const parsed = schema.safeParse(value);
    if (!parsed.success)
      throw new Error("the server returned invalid feedback; refresh and try again");
    return parsed.data;
  }
  return {
    list: (path, cursor, signal, state) =>
      request(
        "?" +
          new URLSearchParams({
            ...(path ? { path } : {}),
            ...(cursor ? { cursor } : {}),
            ...(state ? { state } : {}),
          }),
        threadPageSchema,
        signal,
      ),
    inspect: (id, signal) => request("/" + encodeURIComponent(id), threadSchema, signal),
    events: (id, cursor, signal) =>
      request(
        "/" +
          encodeURIComponent(id) +
          "/events" +
          (cursor === undefined ? "" : "?after_cursor=" + cursor),
        eventPageSchema,
        signal,
      ),
    evidence: async (signal) =>
      (
        await request(
          "/evidence",
          BrowserFeedbackEvidence.extend({
            schema_version: z.literal(1),
            failed_requests: evidenceSchema.shape.failed_requests,
          }),
          signal,
        )
      ).failed_requests,
    report: (input, key, signal) =>
      request("", threadSchema, signal, reportInputSchema.parse(input), key),
    append: (id, type, text, key, signal) =>
      request(
        "/" + encodeURIComponent(id) + "/events",
        eventSchema,
        signal,
        BrowserFeedbackEventRequest.parse({ schema_version: 1, type, ...(text ? { text } : {}) }),
        key,
      ),
  };
}
