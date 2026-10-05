import * as z from "zod/mini";
import {
  evidenceSchema,
  eventPageSchema,
  eventSchema,
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

export interface FeedbackAPI {
  list(path: string, cursor: string | undefined, signal: AbortSignal): Promise<ThreadPage>;
  inspect(id: string, signal: AbortSignal): Promise<Thread>;
  events(id: string, cursor: number | undefined, signal: AbortSignal): Promise<EventPage>;
  evidence(signal: AbortSignal): Promise<Evidence["failed_requests"]>;
  report(input: ReportInput, key: string, signal: AbortSignal): Promise<Thread>;
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
    schema: z.ZodMiniType<T>,
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
    list: (path, cursor, signal) =>
      request(
        "?" + new URLSearchParams({ path, ...(cursor ? { cursor } : {}) }),
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
      (await request("/evidence", z.pick(evidenceSchema, { failed_requests: true }), signal))
        .failed_requests,
    report: (input, key, signal) => request("", threadSchema, signal, input, key),
    append: (id, type, text, key, signal) =>
      request(
        "/" + encodeURIComponent(id) + "/events",
        eventSchema,
        signal,
        { type, ...(text ? { text } : {}) },
        key,
      ),
  };
}
