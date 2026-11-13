// generated from contracts/control/public/v1 with @hey-api/openapi-ts; do not edit.

import * as z from "zod";

/**
 * Verified publisher-to-target TLS. CA is system (the default), aws-rds, or PEM-encoded CA certificates; never a path or URL. aws-rds selects only the supplied endpoint's regional roots offline and requires its hostname for verification. Reads return captured CA material, not a discovery credential.
 */
export const deploymentTargetTlsSchema = z.strictObject({
  ca: z.string().max(1048576).optional(),
  hostname: z.string().min(1).max(253).optional(),
});

export const createDeploymentPublisherEnrollmentRequestSchema = z.strictObject({
  services: z
    .array(z.string().regex(/^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$/))
    .min(1)
    .max(128),
  max_members: z.int().gte(1).lte(256).optional().default(1),
  expires_in: z.int().gte(60).lte(86400).optional().default(600),
});

export const deploymentTargetSchema = z.strictObject({
  address: z.string().min(1).max(8192),
  tls: deploymentTargetTlsSchema.optional(),
});

export const deploymentTargetsSchema = z.record(z.string(), deploymentTargetSchema);

export const createDeploymentRequestSchema = z.strictObject({
  name: z.string().regex(/^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$/),
  targets: deploymentTargetsSchema,
});

/**
 * Update addresses and TLS for selected existing bindings. Omitted services, visitor policy, hostname ownership, service names/protocols, and publisher authority remain unchanged. Does not add or remove bindings.
 */
export const updateDeploymentRequestSchema = z.strictObject({
  targets: deploymentTargetsSchema,
});

/**
 * Exact provider selector resolved by the assigned publisher with its own AWS credentials. Control does not discover targets or credentials. EKS requires kubernetes; RDS requires postgres or mysql, verified against provider metadata.
 */
export const projectTargetDiscoverySchema = z.strictObject({
  type: z.enum(["eks", "rds"]),
  region: z.string().max(64),
  cluster: z.string().max(100).optional(),
  instance: z.string().max(100).optional(),
  endpoint: z.enum(["writer", "reader"]).optional(),
});

/**
 * One saved explicit address/TLS binding or a publisher-side discovery declaration saved by manager apply. Runtime mutations accept explicit addresses only and never evaluate these discovery declarations on control.
 */
export const deploymentTargetStatusSchema = z.strictObject({
  app: z.literal(true).optional(),
  address: z.string().min(1).max(8192).optional(),
  tls: deploymentTargetTlsSchema.optional(),
  discovery: projectTargetDiscoverySchema.optional(),
});

/**
 * Deployment metadata reported by a deployment publisher and covered by its signed runtime assertion. It is not cloud attestation or permission. Values cannot change within a process run; deployment, provider, replica, and instance remain bound to the publisher identity across restarts.
 */
export const publisherDeploymentReportSchema = z.strictObject({
  deployment_id: z
    .string()
    .max(48)
    .regex(/^[a-z0-9][a-z0-9-]{0,47}$/),
  provider: z.enum(["aws"]),
  replica_key: z
    .string()
    .max(32)
    .regex(/^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$/),
  instance: z
    .string()
    .max(32)
    .regex(/^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$/),
  image: z
    .string()
    .max(512)
    .regex(/^[a-z0-9.-]+(:[0-9]+)?\/[a-z0-9._\/-]+@sha256:[a-f0-9]{64}$/),
  software_version: z
    .string()
    .max(64)
    .regex(/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/),
  template_version: z
    .string()
    .max(32)
    .regex(/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,31}$/),
  template_sha256: z
    .string()
    .max(64)
    .regex(/^[a-f0-9]{64}$/),
});

/**
 * An accepted publisher deployment report, with control receipt times and a control-derived deployment_id. It does not prove cloud state, image identity, or target health. The deployment/deployment/replica combination belongs to this publisher identity.
 */
export const publisherDeploymentObservationSchema = z.strictObject({
  report: publisherDeploymentReportSchema,
  deployment_id: z.string(),
  evidence: z.enum(["publisher_reported"]),
  first_observed_at: z.iso.datetime({ offset: true }),
  observed_at: z.iso.datetime({ offset: true }),
});

/**
 * Last explicitly started runtime for this publisher identity, retained after stop or lease expiry. Active means its lease is live, not that the target is reachable or its egress IP is fixed. The source address seen by control can differ from the address used to reach targets and grants no access.
 */
export const publisherRuntimeStatusSchema = z.strictObject({
  publisher_identity_id: z.string(),
  team_id: z.string(),
  process_run_id: z.string(),
  epoch: z.string().regex(/^[0-9]+$/),
  evidence: z.enum(["control_observed"]),
  address: z.string().optional(),
  address_family: z.enum(["ipv4", "ipv6", "unknown"]),
  started_at: z.iso.datetime({ offset: true }),
  observed_at: z.iso.datetime({ offset: true }),
  last_seen_at: z.iso.datetime({ offset: true }),
  lease_expires_at: z.iso.datetime({ offset: true }),
  stopped_at: z.iso.datetime({ offset: true }).optional(),
  active: z.boolean(),
  deployment: publisherDeploymentObservationSchema.optional(),
});

export const serviceProtocolSchema = z.enum(["http", "tcp", "mysql", "postgres", "kubernetes"]);

/**
 * Privately deliver the bounded enrollment key to the publisher. deployment_id is the selected deployment ID. Recovery preserves this secret, captured scope, capacity, and expiration; it never renews or replaces exhausted setup authority.
 */
export const deploymentPublisherEnrollmentSchema = z.strictObject({
  enrollment_id: z.string(),
  enrollment_key: z.string(),
  deployment_id: z.string(),
  expires_at: z.iso.datetime({ offset: true }),
  max_members: z.int().gte(1).lte(256),
  services: z.record(z.string(), serviceProtocolSchema),
});

/**
 * One publisher in the selected deployment (deployment_id), including its retained last observation after revocation. No enrollment secret, signing key, access token, or target is returned. Healthy reports configuration acknowledgement and a current lease, not database login or SQL readiness.
 */
export const deploymentPublisherSchema = z.strictObject({
  team_id: z.string(),
  project_key: z.string(),
  deployment_id: z.string(),
  deployment_name: z.string(),
  publisher_identity_id: z.string(),
  key_id: z.string(),
  observed_revision: z.string().regex(/^[0-9]+$/),
  current_revision: z.string().regex(/^[0-9]+$/),
  snapshot_at: z.iso.datetime({ offset: true }),
  acknowledged_at: z.iso.datetime({ offset: true }).optional(),
  healthy: z.boolean(),
  lease_expires_at: z.iso.datetime({ offset: true }).optional(),
  runtime: publisherRuntimeStatusSchema.optional(),
  services: z.record(z.string(), serviceProtocolSchema),
  revoked_at: z.iso.datetime({ offset: true }).optional(),
});

export const deploymentPublisherPageSchema = z.strictObject({
  publishers: z.array(deploymentPublisherSchema).max(100),
  next_cursor: z.string().optional(),
});

/**
 * Control-owned service TLS identity. Native clients verify this name with system roots. Port is zero when no public ingress reservation exists; a positive port remains reserved when public access is temporarily disabled. It is never a machine-local connector port. Public access requires an allocated port. Target trust is a separate publisher-side boundary.
 */
export const serviceEndpointSchema = z.strictObject({
  hostname: z.string().min(1).max(253),
  port: z.int().gte(0).lte(65535),
  public: z.boolean(),
});

export const resourceIdSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^\S(?:.*\S)?$/);

export const deploymentServiceSchema = z.strictObject({
  id: resourceIdSchema,
  protocol: serviceProtocolSchema,
  trust_revision: z.int().gte(1),
  endpoint: serviceEndpointSchema.optional(),
  public_url: z.url().optional(),
});

export const deploymentSchema = z.strictObject({
  id: z.string(),
  team_id: resourceIdSchema,
  project_key: z.string(),
  name: z.string(),
  revision: z.int().gte(1),
  targets: z.record(z.string(), deploymentTargetStatusSchema),
  services: z.record(z.string(), deploymentServiceSchema),
});

export const deploymentPageSchema = z.strictObject({
  deployments: z.array(deploymentSchema).max(100),
  next_cursor: z.string().optional(),
});

export const problemCodeSchema = z.enum([
  "invalid_request",
  "traffic_selection_invalid",
  "unauthenticated",
  "forbidden",
  "guest_demo_only",
  "guest_ip_changed",
  "guest_issuance_limited",
  "guest_trial_exhausted",
  "not_found",
  "conflict",
  "credential_delivery_unavailable",
  "stale_network_binding",
  "project_managed",
  "rate_limited",
  "unavailable",
  "internal",
  "name_unavailable",
  "publish_run_open",
  "policy_revision_stale",
  "dns_setup_pending",
  "placement_unavailable",
  "member_hostname_depth_exceeded",
  "issuance_retry",
]);

export const problemSchema = z.strictObject({
  type: z.url(),
  title: z.string().min(1),
  status: z.int().gte(400).lte(599),
  code: problemCodeSchema,
  request_id: z.string().min(1),
  detail: z.string().min(1),
  retry_at: z.iso.datetime({ offset: true }).optional(),
  details: z.record(z.string(), z.unknown()).optional(),
});

export const teamIdQuerySchema = resourceIdSchema;

/**
 * Authorized deployment page
 */
export const listDeploymentsResponseSchema = deploymentPageSchema;

/**
 * Created or recovered deployment
 */
export const createDeploymentResponseSchema = deploymentSchema;

/**
 * Deployment retired
 */
export const deleteDeploymentResponseSchema = z.void();

/**
 * Saved deployment
 */
export const getDeploymentResponseSchema = deploymentSchema;

/**
 * Updated deployment
 */
export const updateDeploymentResponseSchema = deploymentSchema;

/**
 * New or recovered bounded enrollment
 */
export const createDeploymentPublisherEnrollmentResponseSchema =
  deploymentPublisherEnrollmentSchema;

/**
 * Deployment publisher page in bytewise publisher ID order
 */
export const listDeploymentPublishersResponseSchema = deploymentPublisherPageSchema;

/**
 * Publisher revoked
 */
export const revokeDeploymentPublisherResponseSchema = z.void();

/**
 * Publisher observation without credentials or targets
 */
export const getDeploymentPublisherResponseSchema = deploymentPublisherSchema;
