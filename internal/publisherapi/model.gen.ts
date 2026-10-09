// generated from api/publisher/v1/openapi.yaml; do not edit.

import { z } from "zod";

// <Schemas>
export type ResourceID = z.infer<typeof ResourceID>;
export const ResourceID = z.string().min(1).max(256).regex(new RegExp("^\\S(?:.*\\S)?$"));

export type ReviewSchemaVersion = z.infer<typeof ReviewSchemaVersion>;
export const ReviewSchemaVersion = z.number().int().min(1);

export type FeedbackThreadState = z.infer<typeof FeedbackThreadState>;
export const FeedbackThreadState = z.enum(["open", "resolved"]);

export type FeedbackEventType = z.infer<typeof FeedbackEventType>;
export const FeedbackEventType = z.enum([
  "thread.created",
  "reply",
  "update",
  "thread.resolved",
  "thread.reopened",
]);

export type FeedbackScope = z.infer<typeof FeedbackScope>;
export const FeedbackScope = z.strictObject({
  preview_id: ResourceID,
  public_url_id: ResourceID,
  publish_run_id: ResourceID,
  publish_run_number: z.number().int().min(1),
  page_path: z.string().min(1).max(2048).regex(new RegExp("^/")),
  page_title: z.string().max(256).optional(),
  service: z.string().min(1).max(32),
});

export type FeedbackAuthor = z.infer<typeof FeedbackAuthor>;
export const FeedbackAuthor = z.strictObject({
  identity_id: ResourceID.optional(),
  display_name: z.string().min(1).max(256),
  verified: z.boolean(),
});

export type FeedbackReport = z.infer<typeof FeedbackReport>;
export const FeedbackReport = z.strictObject({
  text: z.string().min(1).max(4000),
  author: FeedbackAuthor.optional(),
  created_at: z.iso.datetime(),
});

export type FeedbackSelectors = z.infer<typeof FeedbackSelectors>;
export const FeedbackSelectors = z
  .array(z.string().min(1).max(512))
  .min(1)
  .max(6)
  .refine((arr) => new Set(arr).size === arr.length, { message: "uniqueItems" });

export type FeedbackTextBoundary = z.infer<typeof FeedbackTextBoundary>;
export const FeedbackTextBoundary = z.strictObject({
  selectors: FeedbackSelectors,
  text_node: z.number().int().min(0).max(65535),
  offset: z.number().int().min(0).max(1048576),
});

export type FeedbackAnchor = z.infer<typeof FeedbackAnchor>;
export const FeedbackAnchor = z.strictObject({
  schema_version: ReviewSchemaVersion,
  selectors: FeedbackSelectors,
  x: z.number().min(0).max(1),
  y: z.number().min(0).max(1),
  selection: z
    .strictObject({
      start: FeedbackTextBoundary,
      end: FeedbackTextBoundary,
      text: z.string().min(1).max(2000),
    })
    .optional(),
});

export type FeedbackElement = z.infer<typeof FeedbackElement>;
export const FeedbackElement = z
  .strictObject({
    role: z.string().max(128),
    label: z.string().max(256),
    test_id: z.string().max(128),
    html: z.string().max(4096),
  })
  .partial();

export type FeedbackEvidence = z.infer<typeof FeedbackEvidence>;
export const FeedbackEvidence = z.strictObject({
  schema_version: ReviewSchemaVersion,
  element: FeedbackElement.optional(),
  actions: z
    .array(
      z.strictObject({
        type: z.enum(["navigation", "click", "submit"]),
        path: z.string().max(2048).optional(),
        label: z.string().max(256).optional(),
        test_id: z.string().max(128).optional(),
      }),
    )
    .max(20),
  failed_requests: z
    .array(
      z.strictObject({
        method: z.string().min(1).max(12),
        path: z.string().min(1).max(2048).regex(new RegExp("^/")),
        status: z.number().int().min(0).max(599),
        duration_ms: z.number().int().min(0).max(600000),
      }),
    )
    .max(20),
});

export type SourceFileState = z.infer<typeof SourceFileState>;
export const SourceFileState = z.strictObject({
  path: z.string().min(1).max(512),
  status: z.enum(["added", "modified", "deleted"]),
  blob_id: z.string().regex(new RegExp("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")).optional(),
  mode: z.string().regex(new RegExp("^100(?:644|755)$")).optional(),
});

export type SourceState = z.infer<typeof SourceState>;
export const SourceState = z.strictObject({
  schema_version: ReviewSchemaVersion,
  head_commit: z.string().regex(new RegExp("^(?:[0-9a-f]{40}|[0-9a-f]{64})?$")),
  project_path: z.string().max(512),
  branch: z.string().max(128),
  changed_files: z.array(SourceFileState).max(64),
  complete: z.boolean(),
});

export type FeedbackThread = z.infer<typeof FeedbackThread>;
export const FeedbackThread = z.strictObject({
  message_count: z.number().int().min(1),
  latest_event_cursor: z.number().int().min(0),
  schema_version: ReviewSchemaVersion,
  id: ResourceID,
  state: FeedbackThreadState,
  scope: FeedbackScope,
  report: FeedbackReport,
  anchor: FeedbackAnchor.optional(),
  evidence: FeedbackEvidence,
  source_at_report: SourceState,
});

export type FeedbackThreadSummary = z.infer<typeof FeedbackThreadSummary>;
export const FeedbackThreadSummary = z.strictObject({
  message_count: z.number().int().min(1),
  latest_event_cursor: z.number().int().min(0),
  schema_version: ReviewSchemaVersion,
  id: ResourceID,
  state: FeedbackThreadState,
  scope: FeedbackScope,
  report: FeedbackReport,
  anchor: FeedbackAnchor.optional(),
});

export type FeedbackThreadPage = z.infer<typeof FeedbackThreadPage>;
export const FeedbackThreadPage = z.strictObject({
  schema_version: ReviewSchemaVersion,
  threads: z.array(FeedbackThreadSummary).max(100),
  next_cursor: ResourceID.optional(),
  event_cursor: z.number().int().min(0),
});

export type FeedbackEvent = z.infer<typeof FeedbackEvent>;
export const FeedbackEvent = z.strictObject({
  schema_version: ReviewSchemaVersion,
  cursor: z.number().int().min(1),
  feedback_id: ResourceID,
  type: FeedbackEventType,
  actor: z.enum(["implementer", "reviewer"]),
  author: FeedbackAuthor.optional(),
  at: z.iso.datetime(),
  text: z.string().min(1).max(4000).optional(),
  evidence: FeedbackEvidence.optional(),
  source_state: SourceState.optional(),
});

export type FeedbackEventPage = z.infer<typeof FeedbackEventPage>;
export const FeedbackEventPage = z.strictObject({
  schema_version: ReviewSchemaVersion,
  events: z.array(FeedbackEvent).max(25),
  next_cursor: z.number().int().min(1).optional(),
  event_cursor: z.number().int().min(0),
});

export type BrowserAccessStatus = z.infer<typeof BrowserAccessStatus>;
export const BrowserAccessStatus = z.strictObject({
  schema_version: ReviewSchemaVersion,
  allowed: z.boolean(),
  preview_id: ResourceID,
  public_url_id: ResourceID,
  publish_run_number: z.number().int().min(1),
  access_method: z.enum(["ip", "share", "team"]).optional(),
  expires_at: z.iso.datetime().optional(),
  reason: z.literal("TNL_IP_POLICY_DENIED").optional(),
});

export type BrowserFeedbackReportRequest = z.infer<typeof BrowserFeedbackReportRequest>;
export const BrowserFeedbackReportRequest = z.strictObject({
  schema_version: ReviewSchemaVersion,
  text: z.string().min(1).max(4000),
  display_name: z.string().max(64).optional(),
  page_path: z.string().min(1).max(2048).regex(new RegExp("^/")),
  page_title: z.string().max(256).optional(),
  anchor: FeedbackAnchor.optional(),
  evidence: FeedbackEvidence,
});

export type BrowserFeedbackEventRequest = z.infer<typeof BrowserFeedbackEventRequest>;
export const BrowserFeedbackEventRequest = z.strictObject({
  schema_version: ReviewSchemaVersion,
  type: z.enum(["reply", "thread.resolved", "thread.reopened"]),
  text: z.string().min(1).max(4000).optional(),
});

export type BrowserFailedRequest = z.infer<typeof BrowserFailedRequest>;
export const BrowserFailedRequest = z.strictObject({
  method: z.string().min(1).max(12),
  path: z.string().min(1).max(2048).regex(new RegExp("^/")),
  status: z.number().int().min(0).max(599),
  duration_ms: z.number().int().min(0).max(600000),
});

export type BrowserFeedbackEvidence = z.infer<typeof BrowserFeedbackEvidence>;
export const BrowserFeedbackEvidence = z.strictObject({
  schema_version: ReviewSchemaVersion,
  failed_requests: z.array(BrowserFailedRequest).max(20),
});

// </Schemas>
