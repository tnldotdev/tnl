import { z } from "zod";
import {
  browserFeedbackEventRequestSchema,
  browserFeedbackReportRequestSchema,
  feedbackAnchorSchema,
  feedbackElementSchema,
  feedbackEventSchema,
  feedbackEventPageSchema,
  feedbackEvidenceSchema,
  feedbackScopeSchema,
  feedbackTextBoundarySchema,
  feedbackThreadPageSchema,
  feedbackThreadSummarySchema,
} from "../browserapi/model.gen.ts";

// read a browser projection of the generated wire schemas. compatible optional
// fields are ignored, and a future anchor can never hide a readable conversation.
export const elementSchema = z.object(feedbackElementSchema.shape);
const boundarySchema = z.object(feedbackTextBoundarySchema.shape);
const selection = feedbackAnchorSchema.shape.selection.unwrap();
export const anchorSchema = z.object({
  ...feedbackAnchorSchema.shape,
  schema_version: z.literal(1),
  selection: z
    .object({ ...selection.shape, start: boundarySchema, end: boundarySchema })
    .optional(),
});
const unsupportedAnchorSchema = z.looseObject({ schema_version: z.int().min(2) });
export const actionSchema = z.object(feedbackEvidenceSchema.shape.actions.element.shape);
const failure = feedbackEvidenceSchema.shape.failed_requests.element;
export const failureSchema = z.object({
  ...failure.shape,
  path: failure.shape.path.refine((value) => !value.includes("?")),
  status: failure.shape.status.refine((status) => status === 0 || status >= 400),
});
export const evidenceSchema = z.object({
  ...feedbackEvidenceSchema.shape,
  schema_version: z.literal(1),
  element: elementSchema.optional(),
  actions: z.array(actionSchema).max(20),
  failed_requests: z.array(failureSchema).max(20),
});
const report = feedbackThreadSummarySchema.shape.report;
const authorSchema = z.object(report.shape.author.unwrap().shape);
export const summarySchema = z.object({
  ...feedbackThreadSummarySchema.shape,
  schema_version: z.literal(1),
  id: feedbackThreadSummarySchema.shape.id.regex(/^fb_[A-Za-z0-9]{22}$/),
  report: z.object({
    ...report.shape,
    created_at: z.iso.datetime({ offset: true }),
    author: authorSchema.optional(),
  }),
  anchor: z.union([anchorSchema, unsupportedAnchorSchema]).optional(),
  scope: z.object(feedbackScopeSchema.pick({ page_path: true, page_title: true }).shape),
});
export const threadSchema = summarySchema.extend({ evidence: evidenceSchema });
export const eventSchema = z.object({
  ...feedbackEventSchema.pick({
    cursor: true,
    feedback_id: true,
    type: true,
    actor: true,
    text: true,
  }).shape,
  schema_version: z.literal(1),
  author: authorSchema.optional(),
  at: z.iso.datetime({ offset: true }),
});
export const threadPageSchema = z.object({
  ...feedbackThreadPageSchema.shape,
  schema_version: z.literal(1),
  threads: z.array(summarySchema).max(100),
});
export const eventPageSchema = z.object({
  ...feedbackEventPageSchema.shape,
  schema_version: z.literal(1),
  events: z.array(eventSchema).max(25),
});
export const reportInputSchema = browserFeedbackReportRequestSchema.extend({
  schema_version: z.literal(1),
  anchor: anchorSchema.optional(),
  evidence: evidenceSchema,
});

export type ElementSnapshot = z.output<typeof elementSchema>;
export type Anchor = z.output<typeof anchorSchema>;
export type AnchorData = NonNullable<z.output<typeof summarySchema>["anchor"]>;
export type TextBoundary = z.output<typeof boundarySchema>;
export type Action = z.output<typeof actionSchema>;
export type Evidence = z.output<typeof evidenceSchema>;
export type Summary = z.output<typeof summarySchema>;
export type Thread = z.output<typeof threadSchema>;
export type FeedbackEvent = z.output<typeof eventSchema>;
export type ThreadPage = z.output<typeof threadPageSchema>;
export type EventPage = z.output<typeof eventPageSchema>;
export type BrowserEvent = z.output<typeof browserFeedbackEventRequestSchema>["type"];
export type ReportInput = z.output<typeof reportInputSchema>;
