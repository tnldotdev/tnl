// generated from contracts/control/public/v1 with @hey-api/openapi-ts; do not edit.

export type ClientOptions = {
  baseUrl: "https://control.example.com" | (string & {});
};

/**
 * Verified publisher-to-target TLS. CA is system (the default), aws-rds, or PEM-encoded CA certificates; never a path or URL. aws-rds selects only the supplied endpoint's regional roots offline and requires its hostname for verification. Reads return captured CA material, not a discovery credential.
 */
export type DeploymentTargetTls = {
  ca?: string;
  hostname?: string;
};

export type CreateDeploymentPublisherEnrollmentRequest = {
  /**
   * Exact existing bindings to approve. Control captures their saved IDs and protocols; future names, reused names, and protocol changes never expand approval.
   */
  services: Array<string>;
  max_members?: number;
  expires_in?: number;
};

/**
 * Privately deliver the bounded enrollment key to the publisher. deployment_id is the selected deployment ID. Recovery preserves this secret, captured scope, capacity, and expiration; it never renews or replaces exhausted setup authority.
 */
export type DeploymentPublisherEnrollment = {
  enrollment_id: string;
  enrollment_key: string;
  deployment_id: string;
  expires_at: string;
  max_members: number;
  services: {
    [key: string]: ServiceProtocol;
  };
};

/**
 * One publisher in the selected deployment (deployment_id), including its retained last observation after revocation. No enrollment secret, signing key, access token, or target is returned. Healthy reports configuration acknowledgement and a current lease, not database login or SQL readiness.
 */
export type DeploymentPublisher = {
  team_id: string;
  project_key: string;
  deployment_id: string;
  deployment_name: string;
  publisher_identity_id: string;
  key_id: string;
  observed_revision: string;
  current_revision: string;
  snapshot_at: string;
  acknowledged_at?: string;
  healthy: boolean;
  lease_expires_at?: string;
  runtime?: PublisherRuntimeStatus;
  /**
   * Captured service/protocol approval, not a claim of current reachability. Services added later are not approved.
   */
  services: {
    [key: string]: ServiceProtocol;
  };
  revoked_at?: string;
};

export type DeploymentPublisherPage = {
  publishers: Array<DeploymentPublisher>;
  next_cursor?: string;
};

export type DeploymentTarget = {
  /**
   * Explicit host:port, or an HTTP origin for a declared HTTP service. Does not evaluate local configuration or discover cloud resources.
   */
  address: string;
  tls?: DeploymentTargetTls;
};

export type DeploymentTargets = {
  [key: string]: DeploymentTarget;
};

/**
 * One saved explicit address/TLS binding or a publisher-side discovery declaration saved by manager apply. Runtime mutations accept explicit addresses only and never evaluate these discovery declarations on control.
 */
export type DeploymentTargetStatus = {
  /**
   * The application supplies its bound HTTP listener at publication time.
   */
  app?: true;
  address?: string;
  tls?: DeploymentTargetTls;
  discovery?: ProjectTargetDiscovery;
};

export type CreateDeploymentRequest = {
  /**
   * Project-unique name; local is reserved for client-side selection.
   */
  name: string;
  targets: DeploymentTargets;
};

/**
 * Update addresses and TLS for selected existing bindings. Omitted services, visitor policy, hostname ownership, service names/protocols, and publisher authority remain unchanged. Does not add or remove bindings.
 */
export type UpdateDeploymentRequest = {
  targets: DeploymentTargets;
};

export type DeploymentService = {
  /**
   * The bound saved service or public URL ID.
   */
  id: ResourceId;
  protocol: ServiceProtocol;
  trust_revision: number;
  endpoint?: ServiceEndpoint;
  /**
   * The saved HTTP public URL when this binding uses one rather than a private service endpoint.
   */
  public_url?: string;
};

export type Deployment = {
  id: string;
  team_id: ResourceId;
  project_key: string;
  name: string;
  revision: number;
  targets: {
    [key: string]: DeploymentTargetStatus;
  };
  services: {
    [key: string]: DeploymentService;
  };
};

export type DeploymentPage = {
  deployments: Array<Deployment>;
  next_cursor?: string;
};

/**
 * Exact provider selector resolved by the assigned publisher with its own AWS credentials. Control does not discover targets or credentials. EKS requires kubernetes; RDS requires postgres or mysql, verified against provider metadata.
 */
export type ProjectTargetDiscovery = {
  type: "eks" | "rds";
  region: string;
  cluster?: string;
  instance?: string;
  endpoint?: "writer" | "reader";
};

/**
 * Deployment metadata reported by a deployment publisher and covered by its signed runtime assertion. It is not cloud attestation or permission. Values cannot change within a process run; deployment, provider, replica, and instance remain bound to the publisher identity across restarts.
 */
export type PublisherDeploymentReport = {
  deployment_id: string;
  provider: "aws";
  replica_key: string;
  instance: string;
  /**
   * Reported digest-pinned image reference, without a tag, scheme or credentials. Control does not inspect the running image.
   */
  image: string;
  software_version: string;
  template_version: string;
  template_sha256: string;
};

/**
 * An accepted publisher deployment report, with control receipt times and a control-derived deployment_id. It does not prove cloud state, image identity, or target health. The deployment/deployment/replica combination belongs to this publisher identity.
 */
export type PublisherDeploymentObservation = {
  report: PublisherDeploymentReport;
  deployment_id: string;
  evidence: "publisher_reported";
  first_observed_at: string;
  observed_at: string;
};

/**
 * Last explicitly started runtime for this publisher identity, retained after stop or lease expiry. Active means its lease is live, not that the target is reachable or its egress IP is fixed. The source address seen by control can differ from the address used to reach targets and grants no access.
 */
export type PublisherRuntimeStatus = {
  publisher_identity_id: string;
  team_id: string;
  process_run_id: string;
  epoch: string;
  evidence: "control_observed";
  /**
   * Canonical public routable IPv4 or IPv6 host, never a CIDR. Absent for private or non-routable sources.
   */
  address?: string;
  address_family: "ipv4" | "ipv6" | "unknown";
  started_at: string;
  observed_at: string;
  last_seen_at: string;
  lease_expires_at: string;
  stopped_at?: string;
  active: boolean;
  deployment?: PublisherDeploymentObservation;
};

export type ServiceProtocol = "http" | "tcp" | "mysql" | "postgres" | "kubernetes";

/**
 * Control-owned service TLS identity. HTTP uses shared port 443 without an exclusive ingress reservation, including when public access is disabled. Other protocols use zero when no public ingress port is reserved; an allocated port remains reserved during temporary disablement. Only public enables ingress access. This port is never a machine-local connector port. Target trust is a separate publisher-side boundary.
 */
export type ServiceEndpoint = {
  hostname: string;
  port: number;
  public: boolean;
};

export type ResourceId = string;

export type ProblemCode =
  | "invalid_request"
  | "traffic_selection_invalid"
  | "unauthenticated"
  | "forbidden"
  | "guest_demo_only"
  | "guest_ip_changed"
  | "guest_issuance_limited"
  | "guest_trial_exhausted"
  | "not_found"
  | "conflict"
  | "credential_delivery_unavailable"
  | "stale_network_binding"
  | "project_managed"
  | "rate_limited"
  | "unavailable"
  | "internal"
  | "name_unavailable"
  | "publish_run_open"
  | "policy_revision_stale"
  | "dns_setup_pending"
  | "placement_unavailable"
  | "member_hostname_depth_exceeded"
  | "issuance_retry";

export type Problem = {
  type: string;
  title: string;
  status: number;
  code: ProblemCode;
  request_id: string;
  detail: string;
  retry_at?: string;
  details?: {
    [key: string]: unknown;
  };
};

export type TeamIdQuery = ResourceId;

export type ListDeploymentsData = {
  body?: never;
  path: {
    project_key: string;
  };
  query: {
    team_id: ResourceId;
    after?: string;
    limit?: number;
  };
  url: "/v1/projects/{project_key}/deployments";
};

export type ListDeploymentsErrors = {
  /**
   * Request failed
   */
  default: Problem;
};

export type ListDeploymentsError = ListDeploymentsErrors[keyof ListDeploymentsErrors];

export type ListDeploymentsResponses = {
  /**
   * Authorized deployment page
   */
  200: DeploymentPage;
};

export type ListDeploymentsResponse = ListDeploymentsResponses[keyof ListDeploymentsResponses];

export type CreateDeploymentData = {
  body: CreateDeploymentRequest;
  headers: {
    "Idempotency-Key": string;
  };
  path: {
    project_key: string;
  };
  query: {
    team_id: ResourceId;
  };
  url: "/v1/projects/{project_key}/deployments";
};

export type CreateDeploymentErrors = {
  /**
   * Request failed
   */
  default: Problem;
};

export type CreateDeploymentError = CreateDeploymentErrors[keyof CreateDeploymentErrors];

export type CreateDeploymentResponses = {
  /**
   * Created or recovered deployment
   */
  201: Deployment;
};

export type CreateDeploymentResponse = CreateDeploymentResponses[keyof CreateDeploymentResponses];

export type DeleteDeploymentData = {
  body?: never;
  headers?: {
    /**
     * Required by the operation; omission returns 428.
     */
    "If-Match"?: string;
  };
  path: {
    project_key: string;
    /**
     * Deployment name or ID within the selected project.
     */
    deployment: string;
  };
  query: {
    team_id: ResourceId;
  };
  url: "/v1/projects/{project_key}/deployments/{deployment}";
};

export type DeleteDeploymentErrors = {
  /**
   * Request failed
   */
  default: Problem;
};

export type DeleteDeploymentError = DeleteDeploymentErrors[keyof DeleteDeploymentErrors];

export type DeleteDeploymentResponses = {
  /**
   * Deployment retired
   */
  204: void;
};

export type DeleteDeploymentResponse = DeleteDeploymentResponses[keyof DeleteDeploymentResponses];

export type GetDeploymentData = {
  body?: never;
  path: {
    project_key: string;
    /**
     * Deployment name or ID within the selected project.
     */
    deployment: string;
  };
  query: {
    team_id: ResourceId;
  };
  url: "/v1/projects/{project_key}/deployments/{deployment}";
};

export type GetDeploymentErrors = {
  /**
   * Request failed
   */
  default: Problem;
};

export type GetDeploymentError = GetDeploymentErrors[keyof GetDeploymentErrors];

export type GetDeploymentResponses = {
  /**
   * Saved deployment
   */
  200: Deployment;
};

export type GetDeploymentResponse = GetDeploymentResponses[keyof GetDeploymentResponses];

export type UpdateDeploymentData = {
  body: UpdateDeploymentRequest;
  headers?: {
    /**
     * Required by the operation; omission returns 428.
     */
    "If-Match"?: string;
  };
  path: {
    project_key: string;
    /**
     * Deployment name or ID within the selected project.
     */
    deployment: string;
  };
  query: {
    team_id: ResourceId;
  };
  url: "/v1/projects/{project_key}/deployments/{deployment}";
};

export type UpdateDeploymentErrors = {
  /**
   * Request failed
   */
  default: Problem;
};

export type UpdateDeploymentError = UpdateDeploymentErrors[keyof UpdateDeploymentErrors];

export type UpdateDeploymentResponses = {
  /**
   * Updated deployment
   */
  200: Deployment;
};

export type UpdateDeploymentResponse = UpdateDeploymentResponses[keyof UpdateDeploymentResponses];

export type CreateDeploymentPublisherEnrollmentData = {
  body: CreateDeploymentPublisherEnrollmentRequest;
  headers: {
    "Idempotency-Key": string;
  };
  path: {
    project_key: string;
    /**
     * Deployment name or ID within the selected project.
     */
    deployment: string;
  };
  query: {
    team_id: ResourceId;
  };
  url: "/v1/projects/{project_key}/deployments/{deployment}/publisher-enrollments";
};

export type CreateDeploymentPublisherEnrollmentErrors = {
  /**
   * Request failed
   */
  default: Problem;
};

export type CreateDeploymentPublisherEnrollmentError =
  CreateDeploymentPublisherEnrollmentErrors[keyof CreateDeploymentPublisherEnrollmentErrors];

export type CreateDeploymentPublisherEnrollmentResponses = {
  /**
   * New or recovered bounded enrollment
   */
  201: DeploymentPublisherEnrollment;
};

export type CreateDeploymentPublisherEnrollmentResponse =
  CreateDeploymentPublisherEnrollmentResponses[keyof CreateDeploymentPublisherEnrollmentResponses];

export type ListDeploymentPublishersData = {
  body?: never;
  path: {
    project_key: string;
    deployment: string;
  };
  query: {
    team_id: ResourceId;
    after?: string;
    limit?: number;
  };
  url: "/v1/projects/{project_key}/deployments/{deployment}/publishers";
};

export type ListDeploymentPublishersErrors = {
  /**
   * Request failed
   */
  default: Problem;
};

export type ListDeploymentPublishersError =
  ListDeploymentPublishersErrors[keyof ListDeploymentPublishersErrors];

export type ListDeploymentPublishersResponses = {
  /**
   * Deployment publisher page in bytewise publisher ID order
   */
  200: DeploymentPublisherPage;
};

export type ListDeploymentPublishersResponse =
  ListDeploymentPublishersResponses[keyof ListDeploymentPublishersResponses];

export type RevokeDeploymentPublisherData = {
  body?: never;
  path: {
    project_key: string;
    deployment: string;
    publisher: string;
  };
  query: {
    team_id: ResourceId;
  };
  url: "/v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}";
};

export type RevokeDeploymentPublisherErrors = {
  /**
   * Request failed
   */
  default: Problem;
};

export type RevokeDeploymentPublisherError =
  RevokeDeploymentPublisherErrors[keyof RevokeDeploymentPublisherErrors];

export type RevokeDeploymentPublisherResponses = {
  /**
   * Publisher revoked
   */
  204: void;
};

export type RevokeDeploymentPublisherResponse =
  RevokeDeploymentPublisherResponses[keyof RevokeDeploymentPublisherResponses];

export type GetDeploymentPublisherData = {
  body?: never;
  path: {
    project_key: string;
    deployment: string;
    publisher: string;
  };
  query: {
    team_id: ResourceId;
  };
  url: "/v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}";
};

export type GetDeploymentPublisherErrors = {
  /**
   * Request failed
   */
  default: Problem;
};

export type GetDeploymentPublisherError =
  GetDeploymentPublisherErrors[keyof GetDeploymentPublisherErrors];

export type GetDeploymentPublisherResponses = {
  /**
   * Publisher observation without credentials or targets
   */
  200: DeploymentPublisher;
};

export type GetDeploymentPublisherResponse =
  GetDeploymentPublisherResponses[keyof GetDeploymentPublisherResponses];
