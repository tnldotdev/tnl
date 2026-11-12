// generated from contracts/publisher/browser/v1/openapi.yaml with @hey-api/openapi-ts; do not edit.

import * as z from "zod";

export const ResourceId = z
  .string()
  .min(1)
  .max(256)
  .regex(/^\S(?:.*\S)?$/);

/**
 * Review data format version; writers currently emit 1. Separate from revisions and publish run numbers.
 */
export const ReviewSchemaVersion = z.int().gte(1);

export const FeedbackThreadState = z.enum(["open", "resolved"]);

export const FeedbackEventType = z.enum([
  "thread.created",
  "reply",
  "update",
  "thread.resolved",
  "thread.reopened",
]);

export const FeedbackScope = z.strictObject({
  preview_id: ResourceId,
  public_url_id: ResourceId,
  publish_run_id: ResourceId,
  publish_run_number: z.string().regex(/^[0-9]+$/),
  page_path: z.string().min(1).max(2048).regex(/^\//),
  page_title: z.string().max(256).optional(),
  service: z.string().min(1).max(32),
});

export const FeedbackAuthor = z.strictObject({
  identity_id: ResourceId.optional(),
  display_name: z.string().min(1).max(256),
  verified: z.boolean(),
});

export const FeedbackReport = z.strictObject({
  text: z.string().min(1).max(4000),
  author: FeedbackAuthor.optional(),
  created_at: z.iso.datetime(),
});

export const FeedbackSelectors = z.array(z.string().min(1).max(512)).min(1).max(6);

export const FeedbackTextBoundary = z.strictObject({
  selectors: FeedbackSelectors,
  text_node: z.int().gte(0).lte(65535),
  offset: z.int().gte(0).lte(1048576),
});

export const FeedbackAnchor = z.strictObject({
  schema_version: ReviewSchemaVersion,
  selectors: FeedbackSelectors,
  x: z.number().gte(0).lte(1),
  y: z.number().gte(0).lte(1),
  selection: z
    .strictObject({
      start: FeedbackTextBoundary,
      end: FeedbackTextBoundary,
      text: z.string().min(1).max(2000),
    })
    .optional(),
});

export const FeedbackElement = z.strictObject({
  role: z.string().max(128).optional(),
  label: z.string().max(256).optional(),
  test_id: z.string().max(128).optional(),
  html: z.string().max(4096).optional(),
});

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
        path: z.string().min(1).max(2048).regex(/^\//),
        status: z.int().gte(0).lte(599),
        duration_ms: z.int().gte(0).lte(600000),
      }),
    )
    .max(20),
});

export const SourceFileState = z.strictObject({
  path: z.string().min(1).max(512),
  status: z.enum(["added", "modified", "deleted"]),
  blob_id: z
    .string()
    .regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/)
    .optional(),
  mode: z
    .string()
    .regex(/^100(?:644|755)$/)
    .optional(),
});

/**
 * Git identifiers captured for one project directory. Compare HEAD, project_path, and changed_files only when both captures are complete. Branch names, staging, and ignored files do not affect matching. File contents and absolute paths are not stored; truncated or unsupported captures are incomplete.
 */
export const SourceState = z.strictObject({
  schema_version: ReviewSchemaVersion,
  head_commit: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})?$/),
  project_path: z.string().max(512),
  branch: z.string().max(128),
  changed_files: z.array(SourceFileState).max(64),
  complete: z.boolean(),
});

export const FeedbackThread = z.strictObject({
  message_count: z.string().regex(/^[0-9]+$/),
  latest_event_cursor: z.string().regex(/^[0-9]+$/),
  schema_version: ReviewSchemaVersion,
  id: ResourceId,
  state: FeedbackThreadState,
  scope: FeedbackScope,
  report: FeedbackReport,
  anchor: FeedbackAnchor.optional(),
  evidence: FeedbackEvidence,
  source_at_report: SourceState,
});

export const FeedbackThreadSummary = z.strictObject({
  message_count: z.string().regex(/^[0-9]+$/),
  latest_event_cursor: z.string().regex(/^[0-9]+$/),
  schema_version: ReviewSchemaVersion,
  id: ResourceId,
  state: FeedbackThreadState,
  scope: FeedbackScope,
  report: FeedbackReport,
  anchor: FeedbackAnchor.optional(),
});

export const FeedbackThreadPage = z.strictObject({
  schema_version: ReviewSchemaVersion,
  threads: z.array(FeedbackThreadSummary).max(100),
  next_cursor: ResourceId.optional(),
  event_cursor: z.string().regex(/^[0-9]+$/),
});

export const FeedbackEvent = z.strictObject({
  schema_version: ReviewSchemaVersion,
  cursor: z.string().regex(/^[0-9]+$/),
  feedback_id: ResourceId,
  type: FeedbackEventType,
  actor: z.enum(["implementer", "reviewer"]),
  author: FeedbackAuthor.optional(),
  at: z.iso.datetime(),
  text: z.string().min(1).max(4000).optional(),
  evidence: FeedbackEvidence.optional(),
  source_state: SourceState.optional(),
});

export const FeedbackEventPage = z.strictObject({
  schema_version: ReviewSchemaVersion,
  events: z.array(FeedbackEvent).max(25),
  next_cursor: z
    .string()
    .regex(/^[0-9]+$/)
    .optional(),
  event_cursor: z.string().regex(/^[0-9]+$/),
});

export const BrowserAccessStatus = z.strictObject({
  schema_version: ReviewSchemaVersion,
  allowed: z.boolean(),
  preview_id: ResourceId,
  public_url_id: ResourceId,
  publish_run_number: z.string().regex(/^[0-9]+$/),
  access_method: z.enum(["anonymous", "share", "team", "visitor"]).optional(),
  expires_at: z.iso.datetime().optional(),
  reason: z.enum(["TNL_VISITOR_ACCESS_DENIED"]).optional(),
});

export const BrowserFeedbackReportRequest = z.strictObject({
  schema_version: ReviewSchemaVersion,
  text: z.string().min(1).max(4000),
  display_name: z.string().max(64).optional(),
  page_path: z.string().min(1).max(2048).regex(/^\//),
  page_title: z.string().max(256).optional(),
  anchor: FeedbackAnchor.optional(),
  evidence: FeedbackEvidence,
});

export const BrowserFeedbackEventRequest = z.strictObject({
  schema_version: ReviewSchemaVersion,
  type: z.enum(["reply", "thread.resolved", "thread.reopened"]),
  text: z.string().min(1).max(4000).optional(),
});

export const BrowserFailedRequest = z.strictObject({
  method: z.string().min(1).max(12),
  path: z.string().min(1).max(2048).regex(/^\//),
  status: z.int().gte(0).lte(599),
  duration_ms: z.int().gte(0).lte(600000),
});

export const BrowserFeedbackEvidence = z.strictObject({
  schema_version: ReviewSchemaVersion,
  failed_requests: z.array(BrowserFailedRequest).max(20),
});

export const FeedbackId = ResourceId;

/**
 * Reuse for retries of one mutation; at most 128 bytes
 */
export const IdempotencyKey = z.string().min(1).max(128);
