// generated from contracts/publisher/browser/v1/openapi.yaml with @hey-api/openapi-ts; do not edit.

import * as z from "zod";

export const resourceIdSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^\S(?:.*\S)?$/);

/**
 * Review data format version; writers currently emit 1. Separate from revisions and publish run numbers.
 */
export const reviewSchemaVersionSchema = z.int().gte(1);

export const feedbackThreadStateSchema = z.enum(["open", "resolved"]);

export const feedbackEventTypeSchema = z.enum([
  "thread.created",
  "reply",
  "update",
  "thread.resolved",
  "thread.reopened",
]);

export const feedbackScopeSchema = z.strictObject({
  preview_id: resourceIdSchema,
  public_url_id: resourceIdSchema,
  publish_run_id: resourceIdSchema,
  publish_run_number: z.int().gte(1),
  page_path: z.string().min(1).max(2048).regex(/^\//),
  page_title: z.string().max(256).optional(),
  service: z.string().min(1).max(32),
});

export const feedbackAuthorSchema = z.strictObject({
  identity_id: resourceIdSchema.optional(),
  display_name: z.string().min(1).max(256),
  verified: z.boolean(),
});

export const feedbackReportSchema = z.strictObject({
  text: z.string().min(1).max(4000),
  author: feedbackAuthorSchema.optional(),
  created_at: z.iso.datetime(),
});

export const feedbackSelectorsSchema = z.array(z.string().min(1).max(512)).min(1).max(6);

export const feedbackTextBoundarySchema = z.strictObject({
  selectors: feedbackSelectorsSchema,
  text_node: z.int().gte(0).lte(65535),
  offset: z.int().gte(0).lte(1048576),
});

export const feedbackAnchorSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  selectors: feedbackSelectorsSchema,
  x: z.number().gte(0).lte(1),
  y: z.number().gte(0).lte(1),
  selection: z
    .strictObject({
      start: feedbackTextBoundarySchema,
      end: feedbackTextBoundarySchema,
      text: z.string().min(1).max(2000),
    })
    .optional(),
});

export const feedbackElementSchema = z.strictObject({
  role: z.string().max(128).optional(),
  label: z.string().max(256).optional(),
  test_id: z.string().max(128).optional(),
  html: z.string().max(4096).optional(),
});

export const feedbackEvidenceSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  element: feedbackElementSchema.optional(),
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

export const sourceFileStateSchema = z.strictObject({
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
 * Bounded Git identifiers for the source present in one project directory. Compare HEAD, project_path, and changed_files only when both records are complete. Branch names and index state do not affect matching. Source bytes and absolute paths are not stored. Ignored files are outside this comparison; an unsupported or truncated capture is incomplete.
 */
export const sourceStateSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  head_commit: z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})?$/),
  project_path: z.string().max(512),
  branch: z.string().max(128),
  changed_files: z.array(sourceFileStateSchema).max(64),
  complete: z.boolean(),
});

export const feedbackThreadSchema = z.strictObject({
  message_count: z.int().gte(1),
  latest_event_cursor: z.int().gte(0),
  schema_version: reviewSchemaVersionSchema,
  id: resourceIdSchema,
  state: feedbackThreadStateSchema,
  scope: feedbackScopeSchema,
  report: feedbackReportSchema,
  anchor: feedbackAnchorSchema.optional(),
  evidence: feedbackEvidenceSchema,
  source_at_report: sourceStateSchema,
});

export const feedbackThreadSummarySchema = z.strictObject({
  message_count: z.int().gte(1),
  latest_event_cursor: z.int().gte(0),
  schema_version: reviewSchemaVersionSchema,
  id: resourceIdSchema,
  state: feedbackThreadStateSchema,
  scope: feedbackScopeSchema,
  report: feedbackReportSchema,
  anchor: feedbackAnchorSchema.optional(),
});

export const feedbackThreadPageSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  threads: z.array(feedbackThreadSummarySchema).max(100),
  next_cursor: resourceIdSchema.optional(),
  event_cursor: z.int().gte(0),
});

export const feedbackEventSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  cursor: z.int().gte(1),
  feedback_id: resourceIdSchema,
  type: feedbackEventTypeSchema,
  actor: z.enum(["implementer", "reviewer"]),
  author: feedbackAuthorSchema.optional(),
  at: z.iso.datetime(),
  text: z.string().min(1).max(4000).optional(),
  evidence: feedbackEvidenceSchema.optional(),
  source_state: sourceStateSchema.optional(),
});

export const feedbackEventPageSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  events: z.array(feedbackEventSchema).max(25),
  next_cursor: z.int().gte(1).optional(),
  event_cursor: z.int().gte(0),
});

export const browserAccessStatusSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  allowed: z.boolean(),
  preview_id: resourceIdSchema,
  public_url_id: resourceIdSchema,
  publish_run_number: z.int().gte(1),
  access_method: z.enum(["anonymous", "share", "team", "visitor"]).optional(),
  expires_at: z.iso.datetime().optional(),
  reason: z.enum(["TNL_VISITOR_ACCESS_DENIED"]).optional(),
});

export const browserFeedbackReportRequestSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  text: z.string().min(1).max(4000),
  display_name: z.string().max(64).optional(),
  page_path: z.string().min(1).max(2048).regex(/^\//),
  page_title: z.string().max(256).optional(),
  anchor: feedbackAnchorSchema.optional(),
  evidence: feedbackEvidenceSchema,
});

export const browserFeedbackEventRequestSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  type: z.enum(["reply", "thread.resolved", "thread.reopened"]),
  text: z.string().min(1).max(4000).optional(),
});

export const browserFailedRequestSchema = z.strictObject({
  method: z.string().min(1).max(12),
  path: z.string().min(1).max(2048).regex(/^\//),
  status: z.int().gte(0).lte(599),
  duration_ms: z.int().gte(0).lte(600000),
});

export const browserFeedbackEvidenceSchema = z.strictObject({
  schema_version: reviewSchemaVersionSchema,
  failed_requests: z.array(browserFailedRequestSchema).max(20),
});

export const feedbackIdSchema = resourceIdSchema;

/**
 * Reuse for retries of one mutation; at most 128 bytes
 */
export const idempotencyKeySchema = z.string().min(1).max(128);
