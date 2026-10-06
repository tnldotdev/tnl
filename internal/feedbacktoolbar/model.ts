import { z } from "zod";
import {
  BrowserFeedbackEventRequest,
  BrowserFeedbackReportRequest,
  FeedbackAnchor,
  FeedbackElement,
  FeedbackEvent as WireEvent,
  FeedbackEventPage as WireEventPage,
  FeedbackEvidence,
  FeedbackScope,
  FeedbackTextBoundary,
  FeedbackThreadPage as WireThreadPage,
  FeedbackThreadSummary,
} from "../publisherapi/model.gen.ts";

// read a browser projection of the generated wire schemas. compatible optional
// fields are ignored, and a future anchor can never hide a readable conversation.
export const elementSchema = z.object(FeedbackElement.shape);
const boundarySchema = z.object(FeedbackTextBoundary.shape);
const selection = FeedbackAnchor.shape.selection.unwrap();
export const anchorSchema = z.object({
  ...FeedbackAnchor.shape,
  schema_version: z.literal(1),
  selection: z
    .object({ ...selection.shape, start: boundarySchema, end: boundarySchema })
    .optional(),
});
const unsupportedAnchorSchema = z.looseObject({ schema_version: z.int().min(2) });
export const actionSchema = z.object(FeedbackEvidence.shape.actions.element.shape);
const failure = FeedbackEvidence.shape.failed_requests.element;
export const failureSchema = z.object({
  ...failure.shape,
  path: failure.shape.path.refine((value) => !value.includes("?")),
  status: failure.shape.status.refine((status) => status === 0 || status >= 400),
});
export const evidenceSchema = z.object({
  ...FeedbackEvidence.shape,
  schema_version: z.literal(1),
  element: elementSchema.optional(),
  actions: z.array(actionSchema).max(20),
  failed_requests: z.array(failureSchema).max(20),
});
const report = FeedbackThreadSummary.shape.report;
export const summarySchema = z.object({
  ...FeedbackThreadSummary.shape,
  schema_version: z.literal(1),
  id: FeedbackThreadSummary.shape.id.regex(/^fb_[A-Za-z0-9]{22}$/),
  report: z.object({
    ...report.shape,
    created_at: z.iso.datetime({ offset: true }),
    author: z.object(report.shape.author.unwrap().shape).optional(),
  }),
  anchor: z.union([anchorSchema, unsupportedAnchorSchema]).optional(),
  scope: z.object(FeedbackScope.pick({ page_path: true, page_title: true }).shape),
});
export const threadSchema = summarySchema.extend({ evidence: evidenceSchema });
export const eventSchema = z.object({
  ...WireEvent.pick({
    cursor: true,
    feedback_id: true,
    type: true,
    actor: true,
    text: true,
  }).shape,
  schema_version: z.literal(1),
  at: z.iso.datetime({ offset: true }),
});
export const threadPageSchema = z.object({
  ...WireThreadPage.shape,
  schema_version: z.literal(1),
  threads: z.array(summarySchema).max(100),
});
export const eventPageSchema = z.object({
  ...WireEventPage.shape,
  schema_version: z.literal(1),
  events: z.array(eventSchema).max(25),
});
export const reportInputSchema = BrowserFeedbackReportRequest.extend({
  schema_version: z.literal(1),
  anchor: anchorSchema.optional(),
  evidence: evidenceSchema,
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
export type BrowserEvent = z.infer<typeof BrowserFeedbackEventRequest>["type"];
export type ReportInput = z.infer<typeof reportInputSchema>;
