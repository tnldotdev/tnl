import * as z from "zod/mini";

const text = (maximum: number) => z.string().check(z.maxLength(maximum));
const path = () => z.string().check(z.startsWith("/"), z.maxLength(2048));
const cursor = () => z.int().check(z.minimum(0), z.maximum(Number.MAX_SAFE_INTEGER));
const feedbackID = z.string().check(z.regex(/^fb_[A-Za-z0-9]{22}$/));

export const pinSchema = z.object({
  kind: z.enum(["page", "element"]),
  role: z.optional(text(128)),
  label: z.optional(text(256)),
  test_id: z.optional(text(128)),
  html: z.optional(text(4096)),
});
export const actionSchema = z.object({
  type: z.enum(["navigation", "click", "submit"]),
  path: z.optional(path()),
  label: z.optional(text(256)),
  test_id: z.optional(text(128)),
});
export const failureSchema = z.object({
  method: text(12).check(z.minLength(1)),
  path: path().check(z.refine((value) => !value.includes("?"))),
  status: z.int().check(z.refine((status) => status === 0 || (status >= 400 && status <= 599))),
  duration_ms: z.int().check(z.minimum(0), z.maximum(600_000)),
});
export const evidenceSchema = z.object({
  actions: z.array(actionSchema).check(z.maxLength(20)),
  failed_requests: z.array(failureSchema).check(z.maxLength(20)),
});
export const summarySchema = z.object({
  id: feedbackID,
  state: z.enum(["open", "resolved"]),
  report: z.object({
    text: text(4000).check(z.minLength(1)),
    created_at: z.iso.datetime({ offset: true }),
  }),
  element: pinSchema,
  scope: z.object({ page_path: path() }),
});
export const threadSchema = z.extend(summarySchema, { evidence: evidenceSchema });
export const eventSchema = z.object({
  cursor: cursor().check(z.minimum(1)),
  feedback_id: feedbackID,
  type: z.enum(["thread.created", "reply", "update", "thread.resolved", "thread.reopened"]),
  actor: z.enum(["implementer", "reviewer"]),
  at: z.iso.datetime({ offset: true }),
  text: z.optional(text(4000).check(z.minLength(1))),
});
export const threadPageSchema = z.object({
  threads: z.array(summarySchema).check(z.maxLength(100)),
  next_cursor: z.optional(feedbackID),
  event_cursor: cursor(),
});
export const eventPageSchema = z.object({
  events: z.array(eventSchema).check(z.maxLength(25)),
  next_cursor: z.optional(cursor().check(z.minimum(1))),
  event_cursor: cursor(),
});

export type Pin = z.infer<typeof pinSchema>;
export type Action = z.infer<typeof actionSchema>;
export type Evidence = z.infer<typeof evidenceSchema>;
export type Summary = z.infer<typeof summarySchema>;
export type Thread = z.infer<typeof threadSchema>;
export type FeedbackEvent = z.infer<typeof eventSchema>;
export type ThreadPage = z.infer<typeof threadPageSchema>;
export type EventPage = z.infer<typeof eventPageSchema>;
export type BrowserEvent = "reply" | "thread.resolved" | "thread.reopened";
export type ReportInput = {
  text: string;
  display_name: string;
  page_path: string;
  element: Pin;
  evidence: Evidence;
};
