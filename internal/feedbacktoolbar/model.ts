import * as z from "zod/mini";

const text = (maximum: number) => z.string().check(z.maxLength(maximum));
const path = () => z.string().check(z.startsWith("/"), z.maxLength(2048));
const cursor = () => z.int().check(z.minimum(0), z.maximum(Number.MAX_SAFE_INTEGER));
const feedbackID = z.string().check(z.regex(/^fb_[A-Za-z0-9]{22}$/));

export const elementSchema = z.object({
  role: z.optional(text(128)),
  label: z.optional(text(256)),
  test_id: z.optional(text(128)),
  html: z.optional(text(4096)),
});
const selectorsSchema = z
  .array(text(512).check(z.minLength(1)))
  .check(z.minLength(1), z.maxLength(6));
const boundarySchema = z.object({
  selectors: selectorsSchema,
  text_node: z.int().check(z.minimum(0), z.maximum(65535)),
  offset: z.int().check(z.minimum(0), z.maximum(1048576)),
});
export const anchorSchema = z.object({
  schema_version: z.literal(1),
  selectors: selectorsSchema,
  x: z.number().check(z.minimum(0), z.maximum(1)),
  y: z.number().check(z.minimum(0), z.maximum(1)),
  selection: z.optional(
    z.object({
      start: boundarySchema,
      end: boundarySchema,
      text: text(2000).check(z.minLength(1)),
    }),
  ),
});
const unsupportedAnchorSchema = z.looseObject({ schema_version: z.int().check(z.minimum(2)) });
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
  schema_version: z.literal(1),
  element: z.optional(elementSchema),
  actions: z.array(actionSchema).check(z.maxLength(20)),
  failed_requests: z.array(failureSchema).check(z.maxLength(20)),
});
export const summarySchema = z.object({
  schema_version: z.literal(1),
  id: feedbackID,
  state: z.enum(["open", "resolved"]),
  report: z.object({
    text: text(4000).check(z.minLength(1)),
    created_at: z.iso.datetime({ offset: true }),
  }),
  anchor: z.optional(z.union([anchorSchema, unsupportedAnchorSchema])),
  scope: z.object({ page_path: path() }),
});
export const threadSchema = z.extend(summarySchema, { evidence: evidenceSchema });
export const eventSchema = z.object({
  schema_version: z.literal(1),
  cursor: cursor().check(z.minimum(1)),
  feedback_id: feedbackID,
  type: z.enum(["thread.created", "reply", "update", "thread.resolved", "thread.reopened"]),
  actor: z.enum(["implementer", "reviewer"]),
  at: z.iso.datetime({ offset: true }),
  text: z.optional(text(4000).check(z.minLength(1))),
});
export const threadPageSchema = z.object({
  schema_version: z.literal(1),
  threads: z.array(summarySchema).check(z.maxLength(100)),
  next_cursor: z.optional(feedbackID),
  event_cursor: cursor(),
});
export const eventPageSchema = z.object({
  schema_version: z.literal(1),
  events: z.array(eventSchema).check(z.maxLength(25)),
  next_cursor: z.optional(cursor().check(z.minimum(1))),
  event_cursor: cursor(),
});

export type ElementSnapshot = z.infer<typeof elementSchema>;
export type Anchor = z.infer<typeof anchorSchema>;
export type AnchorData = NonNullable<z.infer<typeof summarySchema>["anchor"]>;
export type TextBoundary = z.infer<typeof boundarySchema>;
export type Action = z.infer<typeof actionSchema>;
export type Evidence = z.infer<typeof evidenceSchema>;
export type Summary = z.infer<typeof summarySchema>;
export type Thread = z.infer<typeof threadSchema>;
export type FeedbackEvent = z.infer<typeof eventSchema>;
export type ThreadPage = z.infer<typeof threadPageSchema>;
export type EventPage = z.infer<typeof eventPageSchema>;
export type BrowserEvent = "reply" | "thread.resolved" | "thread.reopened";
export type ReportInput = {
  schema_version: 1;
  text: string;
  display_name: string;
  page_path: string;
  anchor?: Anchor | undefined;
  evidence: Evidence;
};
