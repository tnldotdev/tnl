import { z } from "zod";
import { FeedbackError } from "./errors.ts";
import {
  BrowserFeedbackEventRequest,
  BrowserFeedbackEvidence,
  BrowserFeedbackAccess,
  BrowserSession,
} from "../publisherapi/model.gen.ts";
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
  access(signal: AbortSignal): Promise<z.infer<typeof BrowserFeedbackAccess>>;
  session(signal: AbortSignal): Promise<z.infer<typeof BrowserSession>>;
  signOut(signal: AbortSignal): Promise<void>;
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
    postingIdentity?: string,
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
    let response: Response;
    try {
      response = await fetcher(path.startsWith("/__tnl/") ? path : "/__tnl/feedback" + path, {
        method: body === undefined ? "GET" : "POST",
        credentials: "same-origin",
        cache: "no-store",
        signal,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch (cause) {
      if (signal.aborted) throw cause;
      throw new FeedbackError("unavailable", { cause });
    }
    if (!response.ok) {
      if (response.status === 403) throw new FeedbackError("access_expired");
      if (response.status === 401) throw new FeedbackError("sign_in_required");
      if (response.status === 404) throw new FeedbackError("not_found");
      if (response.status === 400) throw new FeedbackError("input_invalid");
      if (response.status === 409) throw new FeedbackError("conflict");
      if (response.status === 429) throw new FeedbackError("rate_limited");
      throw new FeedbackError("unavailable");
    }
    let value: unknown;
    try {
      value = JSON.parse(await readResponse(response)) as unknown;
    } catch (cause) {
      throw new FeedbackError("response_invalid", { cause });
    }
    const parsed = schema.safeParse(value);
    if (!parsed.success) throw new FeedbackError("response_invalid", { cause: parsed.error });
    return parsed.data;
  }
  return {
    access: async (signal) => {
      const access = await request("/access", BrowserFeedbackAccess, signal);
      if ((access.identity_state === "signed_in") !== (access.identity !== undefined))
        throw new FeedbackError("response_invalid");
      return access;
    },
    session: async (signal) => {
      const session = await request("/__tnl/team/session", BrowserSession, signal);
      if (
        session.signed_in &&
        (session.display_name === undefined || session.visit_allowed === undefined)
      )
        throw new FeedbackError("response_invalid");
      if (
        !session.signed_in &&
        (session.display_name !== undefined || session.visit_allowed !== undefined)
      )
        throw new FeedbackError("response_invalid");
      return session;
    },
    signOut: async (signal) => {
      let response: Response;
      try {
        response = await fetcher("/__tnl/team/logout", {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          signal,
        });
      } catch (cause) {
        if (signal.aborted) throw cause;
        throw new FeedbackError("unavailable", { cause });
      }
      if (response.status === 401) throw new FeedbackError("sign_in_required");
      if (response.status === 403) throw new FeedbackError("access_expired");
      if (response.status !== 204) throw new FeedbackError("unavailable");
    },
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
      request("", threadSchema, signal, parseInput(input, reportInputSchema), key),
    append: (id, type, text, key, signal, postingIdentity) =>
      request(
        "/" + encodeURIComponent(id) + "/events",
        eventSchema,
        signal,
        parseInput(
          {
            schema_version: 1,
            type,
            ...(text ? { text } : {}),
            ...(postingIdentity ? { posting_identity: postingIdentity } : {}),
          },
          BrowserFeedbackEventRequest,
        ),
        key,
      ),
  };
}

async function readResponse(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) throw new FeedbackError("response_invalid");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let size = 0;
  let text = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return text + decoder.decode();
      size += value.byteLength;
      if (size > 1 << 20) {
        await reader.cancel();
        throw new FeedbackError("response_invalid");
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

function parseInput<T>(value: unknown, schema: z.ZodType<T>): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new FeedbackError("input_invalid", { cause: result.error });
  return result.data;
}
