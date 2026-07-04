-- +goose Up
CREATE SCHEMA IF NOT EXISTS control;

CREATE TABLE control.identities (
    id text PRIMARY KEY CHECK (id <> ''),
    kind text NOT NULL CHECK (kind IN ('builtin', 'oidc', 'authority')),
    issuer text,
    subject text,
    display_name text NOT NULL CHECK (display_name <> ''),
    normalized_email text,
    email_verified boolean NOT NULL DEFAULT false,
    administrator boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    disabled_at timestamptz,
    CHECK ((issuer IS NULL) = (subject IS NULL)),
    CHECK (kind = 'oidc' OR issuer IS NULL),
    CHECK (normalized_email IS NOT NULL OR NOT email_verified),
    CHECK (updated_at >= created_at),
    CHECK (disabled_at IS NULL OR disabled_at >= created_at)
);

CREATE UNIQUE INDEX identities_oidc_subject
    ON control.identities (issuer, subject)
    WHERE issuer IS NOT NULL;
CREATE UNIQUE INDEX identities_builtin_singleton
    ON control.identities (kind)
    WHERE kind = 'builtin';

CREATE TABLE control.managed_label_reservations (
    label text PRIMARY KEY CHECK (label <> ''),
    created_at timestamptz NOT NULL
);

CREATE TABLE control.teams (
    id text PRIMARY KEY CHECK (id <> ''),
    kind text NOT NULL CHECK (kind IN ('personal', 'organization')),
    display_name text NOT NULL CHECK (display_name <> ''),
    managed_label text NOT NULL UNIQUE REFERENCES control.managed_label_reservations(label) ON DELETE RESTRICT,
    default_domain_id text,
    policy_revision bigint NOT NULL DEFAULT 1 CHECK (policy_revision >= 1),
    created_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    creation_idempotency_key text,
    creation_request_digest bytea,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    CHECK ((creation_idempotency_key IS NULL) = (creation_request_digest IS NULL)),
    CHECK (creation_idempotency_key IS NULL OR creation_idempotency_key <> ''),
    CHECK (creation_request_digest IS NULL OR octet_length(creation_request_digest) = 32),
    CHECK (updated_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at)
);

CREATE TABLE control.member_slug_reservations (
    id text PRIMARY KEY CHECK (id <> ''),
    team_id text NOT NULL REFERENCES control.teams(id) ON DELETE RESTRICT,
    member_slug text NOT NULL CHECK (member_slug <> ''),
    state text NOT NULL CHECK (state IN ('invited', 'active', 'quarantined', 'released')),
    reserved_by_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    activated_at timestamptz,
    quarantined_at timestamptz,
    reusable_after timestamptz,
    released_at timestamptz,
    UNIQUE (team_id, member_slug),
    CHECK (activated_at IS NULL OR activated_at >= created_at),
    CHECK (quarantined_at IS NULL OR quarantined_at >= created_at),
    CHECK (reusable_after IS NULL OR quarantined_at IS NOT NULL),
    CHECK ((state = 'released') = (released_at IS NOT NULL))
);

CREATE UNIQUE INDEX teams_personal_creator
    ON control.teams (created_by_identity_id)
    WHERE kind = 'personal' AND deleted_at IS NULL;
CREATE UNIQUE INDEX teams_creator_idempotency
    ON control.teams (created_by_identity_id, creation_idempotency_key)
    WHERE creation_idempotency_key IS NOT NULL;

CREATE TABLE control.team_memberships (
    id text PRIMARY KEY CHECK (id <> ''),
    team_id text NOT NULL REFERENCES control.teams(id) ON DELETE RESTRICT,
    identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    slug_reservation_id text NOT NULL REFERENCES control.member_slug_reservations(id) ON DELETE RESTRICT,
    managed_label text NOT NULL UNIQUE REFERENCES control.managed_label_reservations(label) ON DELETE RESTRICT,
    role text NOT NULL CHECK (role IN ('member', 'admin', 'owner')),
    authority_revision bigint NOT NULL CHECK (authority_revision >= 1),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    removed_at timestamptz,
    removed_by_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at),
    CHECK (removed_at IS NULL OR removed_at >= created_at),
    CHECK ((removed_at IS NULL) = (removed_by_identity_id IS NULL))
);

CREATE UNIQUE INDEX team_memberships_current_identity
    ON control.team_memberships (team_id, identity_id)
    WHERE removed_at IS NULL;
CREATE UNIQUE INDEX team_memberships_current_slug
    ON control.team_memberships (slug_reservation_id)
    WHERE removed_at IS NULL;
CREATE INDEX team_memberships_identity
    ON control.team_memberships (identity_id, team_id)
    WHERE removed_at IS NULL;

CREATE TABLE control.team_invitations (
    id text PRIMARY KEY CHECK (id <> ''),
    team_id text NOT NULL REFERENCES control.teams(id) ON DELETE RESTRICT,
    slug_reservation_id text NOT NULL REFERENCES control.member_slug_reservations(id) ON DELETE RESTRICT,
    initial_role text NOT NULL CHECK (initial_role IN ('member', 'admin', 'owner')),
    invited_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    normalized_email_restriction text,
    state text NOT NULL CHECK (state IN ('pending', 'accepted', 'revoked', 'expired')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    accepted_by_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    accepted_membership_id text REFERENCES control.team_memberships(id) ON DELETE RESTRICT,
    revoked_at timestamptz,
    revoked_by_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    CHECK (expires_at > created_at),
    CHECK ((state = 'accepted') = (accepted_at IS NOT NULL)),
    CHECK ((accepted_at IS NULL) = (accepted_by_identity_id IS NULL)),
    CHECK ((accepted_at IS NULL) = (accepted_membership_id IS NULL)),
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK ((revoked_at IS NULL) = (revoked_by_identity_id IS NULL)),
    UNIQUE (team_id, invited_by_identity_id, idempotency_key)
);

CREATE INDEX team_invitations_pending
    ON control.team_invitations (team_id, expires_at)
    WHERE state = 'pending';

CREATE TABLE control.dns_authorities (
    authority_reference text PRIMARY KEY CHECK (authority_reference <> ''),
    team_id text NOT NULL CHECK (team_id <> ''),
    domain_id text NOT NULL UNIQUE CHECK (domain_id <> ''),
    canonical_domain text NOT NULL CHECK (canonical_domain <> ''),
    create_idempotency_key text NOT NULL UNIQUE CHECK (create_idempotency_key <> ''),
    create_request_digest bytea NOT NULL CHECK (octet_length(create_request_digest) = 32),
    release_idempotency_key text UNIQUE CHECK (release_idempotency_key IS NULL OR release_idempotency_key <> ''),
    provider text NOT NULL CHECK (provider <> ''),
    provider_zone_id text,
    state text NOT NULL CHECK (state IN ('pending', 'ready', 'releasing', 'released', 'failed')),
    nameservers text[] NOT NULL DEFAULT '{}'::text[],
    work_revision bigint NOT NULL DEFAULT 1 CHECK (work_revision >= 1),
    work_owner text,
    work_epoch bigint NOT NULL DEFAULT 0 CHECK (work_epoch >= 0),
    work_expires_at timestamptz,
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL,
    last_error text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((work_owner IS NULL) = (work_expires_at IS NULL)),
    CHECK (updated_at >= created_at)
);

CREATE INDEX dns_authorities_available_work
    ON control.dns_authorities (available_at, authority_reference)
    WHERE state IN ('pending', 'releasing');

CREATE TABLE control.domains (
    id text PRIMARY KEY CHECK (id <> ''),
    kind text NOT NULL CHECK (kind IN ('managed', 'claimed')),
    team_id text REFERENCES control.teams(id) ON DELETE RESTRICT,
    canonical_domain text NOT NULL CHECK (canonical_domain <> ''),
    dns_authority_reference text REFERENCES control.dns_authorities(authority_reference) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN ('pending', 'ready', 'releasing', 'released', 'failed')),
    authority_revision bigint NOT NULL CHECK (authority_revision >= 1),
    verification_token_digest bytea CHECK (verification_token_digest IS NULL OR octet_length(verification_token_digest) = 32),
    created_by_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    claim_idempotency_key text,
    claim_request_digest bytea,
    make_default_when_ready boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    verified_at timestamptz,
    reusable_after timestamptz,
    released_at timestamptz,
    updated_at timestamptz NOT NULL,
    CHECK ((kind = 'managed' AND team_id IS NULL) OR (kind = 'claimed' AND team_id IS NOT NULL)),
    CHECK ((claim_idempotency_key IS NULL) = (claim_request_digest IS NULL)),
    CHECK (claim_idempotency_key IS NULL OR claim_idempotency_key <> ''),
    CHECK (claim_request_digest IS NULL OR octet_length(claim_request_digest) = 32),
    CHECK (updated_at >= created_at),
    CHECK (verified_at IS NULL OR verified_at >= created_at),
    CHECK ((state = 'released') = (released_at IS NOT NULL))
);

CREATE UNIQUE INDEX domains_current_canonical_domain
    ON control.domains (canonical_domain)
    WHERE released_at IS NULL;
CREATE UNIQUE INDEX domains_managed_deployment_domain
    ON control.domains (kind)
    WHERE kind = 'managed' AND released_at IS NULL;
CREATE INDEX domains_team
    ON control.domains (team_id, canonical_domain)
    WHERE released_at IS NULL;
CREATE UNIQUE INDEX domains_creator_idempotency
    ON control.domains (team_id, created_by_identity_id, claim_idempotency_key)
    WHERE claim_idempotency_key IS NOT NULL;

ALTER TABLE control.teams
    ADD CONSTRAINT teams_default_domain_id_fkey
    FOREIGN KEY (default_domain_id) REFERENCES control.domains(id) ON DELETE RESTRICT;

CREATE TABLE control.control_sessions (
    id text PRIMARY KEY CHECK (id <> ''),
    identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    authentication_method text NOT NULL CHECK (authentication_method IN ('login_token', 'oidc')),
    authentication_source_revision bigint NOT NULL CHECK (authentication_source_revision >= 1),
    administrator boolean NOT NULL DEFAULT false,
    access_token_id text NOT NULL UNIQUE CHECK (access_token_id <> ''),
    access_token_digest bytea NOT NULL UNIQUE CHECK (octet_length(access_token_digest) = 32),
    access_expires_at timestamptz NOT NULL,
    refresh_token_id text NOT NULL UNIQUE CHECK (refresh_token_id <> ''),
    refresh_token_digest bytea NOT NULL UNIQUE CHECK (octet_length(refresh_token_digest) = 32),
    retry_secret_ciphertext bytea NOT NULL CHECK (octet_length(retry_secret_ciphertext) > 29),
    retry_secret_storage_key_id text NOT NULL CHECK (retry_secret_storage_key_id <> ''),
    refresh_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    last_refreshed_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revoked_by text,
    CHECK (access_expires_at > created_at),
    CHECK (refresh_expires_at >= access_expires_at),
    CHECK (last_refreshed_at >= created_at),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX control_sessions_identity
    ON control.control_sessions (identity_id, created_at DESC);
CREATE INDEX control_sessions_authentication_source
    ON control.control_sessions (authentication_method, authentication_source_revision)
    WHERE revoked_at IS NULL;

CREATE TABLE control.authority_revision_state (
    issuer text NOT NULL CHECK (issuer <> ''),
    team_id text NOT NULL CHECK (team_id <> ''),
    observed_policy_revision bigint NOT NULL DEFAULT 0 CHECK (observed_policy_revision >= 0),
    applied_policy_revision bigint NOT NULL DEFAULT 0 CHECK (applied_policy_revision >= 0),
    observed_at timestamptz,
    applied_at timestamptz,
    CHECK ((observed_policy_revision = 0) = (observed_at IS NULL)),
    CHECK ((applied_policy_revision = 0) = (applied_at IS NULL)),
    PRIMARY KEY (issuer, team_id)
);

CREATE TABLE control.runtime_secrets (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    external_retry_master_key_ciphertext bytea NOT NULL CHECK (octet_length(external_retry_master_key_ciphertext) > 29),
    external_retry_master_key_storage_key_id text NOT NULL CHECK (external_retry_master_key_storage_key_id <> ''),
    created_at timestamptz NOT NULL
);

CREATE TABLE control.routes (
    id text PRIMARY KEY CHECK (id <> ''),
    team_id text NOT NULL CHECK (team_id <> ''),
    domain_id text NOT NULL CHECK (domain_id <> ''),
    membership_id text,
    created_by_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    canonical_hostname text NOT NULL CHECK (canonical_hostname <> ''),
    target text NOT NULL CHECK (target <> ''),
    route_scope text NOT NULL CHECK (route_scope IN ('member', 'shared')),
    policy_revision bigint NOT NULL CHECK (policy_revision >= 1),
    ip_policy text NOT NULL CHECK (ip_policy IN ('allow_all', 'allowlist')),
    allowed_ip_prefixes cidr[] NOT NULL DEFAULT '{}'::cidr[],
    lifecycle_state text NOT NULL CHECK (lifecycle_state IN ('enabled', 'suspended', 'deleted')),
    dns_authority_reference text,
    dns_state text NOT NULL CHECK (dns_state IN ('unmanaged', 'pending', 'published', 'removing', 'removed', 'failed')),
    dns_revision bigint NOT NULL DEFAULT 1 CHECK (dns_revision >= 1),
    dns_work_owner text,
    dns_work_epoch bigint NOT NULL DEFAULT 0 CHECK (dns_work_epoch >= 0),
    dns_work_expires_at timestamptz,
    dns_attempts bigint NOT NULL DEFAULT 0 CHECK (dns_attempts >= 0),
    dns_available_at timestamptz,
    dns_last_error text,
    next_route_version bigint NOT NULL DEFAULT 1 CHECK (next_route_version >= 1),
    mutation_revision bigint NOT NULL DEFAULT 1 CHECK (mutation_revision >= 1),
    ephemeral boolean NOT NULL DEFAULT false,
    expires_at timestamptz,
    suspension_revision bigint NOT NULL DEFAULT 0 CHECK (suspension_revision >= 0),
    suspension_reason text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    suspended_at timestamptz,
    deleted_at timestamptz,
    CHECK ((route_scope = 'member') = (membership_id IS NOT NULL)),
    CHECK ((ip_policy = 'allowlist') = (cardinality(allowed_ip_prefixes) > 0)),
    CHECK (cardinality(allowed_ip_prefixes) <= 64),
    CHECK (array_position(allowed_ip_prefixes, NULL) IS NULL),
    CHECK (ephemeral = (expires_at IS NOT NULL)),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK ((dns_work_owner IS NULL) = (dns_work_expires_at IS NULL)),
    CHECK ((dns_state IN ('pending', 'removing')) = (dns_available_at IS NOT NULL)),
    CHECK (dns_authority_reference IS NULL OR dns_authority_reference <> ''),
    CHECK (updated_at >= created_at),
    CHECK ((lifecycle_state = 'suspended') = (suspended_at IS NOT NULL)),
    CHECK ((lifecycle_state = 'deleted') = (deleted_at IS NOT NULL)),
    CHECK (suspension_reason IS NULL OR suspension_revision > 0)
);

CREATE UNIQUE INDEX routes_current_hostname
    ON control.routes (canonical_hostname)
    WHERE lifecycle_state <> 'deleted' OR dns_state NOT IN ('unmanaged', 'removed');
CREATE UNIQUE INDEX routes_creator_idempotency
    ON control.routes (created_by_identity_id, idempotency_key);
CREATE INDEX routes_team
    ON control.routes (team_id, created_at DESC, id)
    WHERE lifecycle_state <> 'deleted';
CREATE INDEX routes_domain
    ON control.routes (domain_id)
    WHERE lifecycle_state <> 'deleted';
CREATE INDEX routes_available_dns_work
    ON control.routes (dns_available_at, id)
    WHERE dns_state IN ('pending', 'removing');
CREATE INDEX routes_ephemeral_expiration
    ON control.routes (expires_at, id)
    WHERE ephemeral AND lifecycle_state <> 'deleted';

CREATE TABLE control.route_sessions (
    id text PRIMARY KEY CHECK (id <> ''),
    route_id text NOT NULL REFERENCES control.routes(id) ON DELETE RESTRICT,
    team_id text NOT NULL CHECK (team_id <> ''),
    membership_id text,
    acting_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    route_version bigint NOT NULL CHECK (route_version >= 1),
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    session_token_id text NOT NULL UNIQUE CHECK (session_token_id <> ''),
    session_token_digest bytea NOT NULL UNIQUE CHECK (octet_length(session_token_digest) = 32),
    policy_revision bigint NOT NULL CHECK (policy_revision >= 1),
    policy_denials bigint NOT NULL DEFAULT 0 CHECK (policy_denials >= 0),
    certificate_cache_key text NOT NULL CHECK (certificate_cache_key <> ''),
    certificate_scope text NOT NULL CHECK (certificate_scope <> ''),
    certificate_identifiers text[] NOT NULL CHECK (cardinality(certificate_identifiers) > 0),
    certificate_challenge text NOT NULL CHECK (certificate_challenge IN ('dns-01', 'tls-alpn-01')),
    state text NOT NULL CHECK (state IN ('starting', 'ready', 'closed', 'expired', 'canceled')),
    created_at timestamptz NOT NULL,
    last_heartbeat_at timestamptz NOT NULL,
    publisher_expires_at timestamptz NOT NULL,
    certificate_installed_at timestamptz,
    certificate_issuance_id text,
    certificate_not_after timestamptz,
    ready_at timestamptz,
    closed_at timestamptz,
    close_reason text,
    UNIQUE (route_id, route_version),
    UNIQUE (route_id, idempotency_key),
    UNIQUE (id, route_id, route_version),
    CHECK (array_position(certificate_identifiers, NULL) IS NULL),
    CHECK (last_heartbeat_at >= created_at),
    CHECK (publisher_expires_at > created_at),
    CHECK (certificate_installed_at IS NULL OR certificate_installed_at >= created_at),
    CHECK ((certificate_installed_at IS NULL) = (certificate_issuance_id IS NULL)),
    CHECK ((certificate_installed_at IS NULL) = (certificate_not_after IS NULL)),
    CHECK (certificate_not_after IS NULL OR certificate_not_after > certificate_installed_at),
    CHECK (state <> 'ready' OR ready_at IS NOT NULL),
    CHECK ((state IN ('starting', 'ready')) = (closed_at IS NULL)),
    CHECK ((closed_at IS NULL) = (close_reason IS NULL))
);

CREATE UNIQUE INDEX route_sessions_nonterminal_route
    ON control.route_sessions (route_id)
    WHERE closed_at IS NULL;
CREATE INDEX route_sessions_expiration
    ON control.route_sessions (publisher_expires_at, id)
    WHERE closed_at IS NULL;

CREATE TABLE control.relay_services (
    relay_service_id text PRIMARY KEY CHECK (relay_service_id <> ''),
    relay_address text NOT NULL CHECK (relay_address <> ''),
    tls_server_name text NOT NULL CHECK (tls_server_name <> ''),
    transport_certificate_pem text,
    transport_private_key_ciphertext bytea,
    transport_private_key_storage_key_id text,
    transport_certificate_serial text,
    transport_certificate_expires_at timestamptz,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
	CHECK (
		(transport_certificate_pem IS NULL AND transport_private_key_ciphertext IS NULL AND transport_private_key_storage_key_id IS NULL AND transport_certificate_serial IS NULL AND transport_certificate_expires_at IS NULL) OR
		(transport_certificate_pem IS NOT NULL AND transport_private_key_ciphertext IS NOT NULL AND transport_private_key_storage_key_id IS NOT NULL AND transport_certificate_serial IS NOT NULL AND transport_certificate_expires_at IS NOT NULL)
	),
    CHECK (updated_at >= created_at)
);

CREATE TABLE control.relay_leases (
    relay_id text PRIMARY KEY CHECK (relay_id <> ''),
    relay_service_id text NOT NULL REFERENCES control.relay_services(relay_service_id) ON DELETE RESTRICT,
    relay_run_id text NOT NULL CHECK (relay_run_id <> ''),
    relay_lease_revision bigint NOT NULL CHECK (relay_lease_revision >= 1),
    protocol_version bigint NOT NULL CHECK (protocol_version >= 1),
    internal_relay_address text NOT NULL CHECK (internal_relay_address <> ''),
    observed_address inet,
    internal_networks cidr[] NOT NULL DEFAULT '{}'::cidr[],
    connection_capacity bigint NOT NULL CHECK (connection_capacity >= 0),
    stream_capacity bigint NOT NULL CHECK (stream_capacity >= 0),
    reported_connections bigint NOT NULL DEFAULT 0 CHECK (reported_connections >= 0),
    reported_streams bigint NOT NULL DEFAULT 0 CHECK (reported_streams >= 0),
    draining boolean NOT NULL DEFAULT false,
    drain_deadline timestamptz,
    registered_at timestamptz NOT NULL,
    renewed_at timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    UNIQUE (relay_id, relay_run_id, relay_lease_revision),
    CHECK (array_position(internal_networks, NULL) IS NULL),
    CHECK (renewed_at >= registered_at),
    CHECK (lease_expires_at > renewed_at),
    CHECK (draining OR drain_deadline IS NULL)
);

CREATE INDEX relay_leases_placement
    ON control.relay_leases (relay_service_id, lease_expires_at, relay_id)
    WHERE NOT draining;

CREATE TABLE control.ingress_leases (
    ingress_id text PRIMARY KEY CHECK (ingress_id <> ''),
    ingress_run_id text NOT NULL CHECK (ingress_run_id <> ''),
    ingress_lease_revision bigint NOT NULL CHECK (ingress_lease_revision >= 1),
    protocol_version bigint NOT NULL CHECK (protocol_version >= 1),
    connection_capacity bigint NOT NULL CHECK (connection_capacity >= 0),
    reported_connections bigint NOT NULL DEFAULT 0 CHECK (reported_connections >= 0),
    routing_table_revision bigint NOT NULL DEFAULT 0 CHECK (routing_table_revision >= 0),
    draining boolean NOT NULL DEFAULT false,
    drain_deadline timestamptz,
    registered_at timestamptz NOT NULL,
    renewed_at timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    UNIQUE (ingress_id, ingress_run_id, ingress_lease_revision),
    CHECK (renewed_at >= registered_at),
    CHECK (lease_expires_at > renewed_at),
    CHECK (draining OR drain_deadline IS NULL)
);

CREATE INDEX ingress_leases_ready
    ON control.ingress_leases (lease_expires_at, ingress_id)
    WHERE NOT draining;

CREATE TABLE control.route_session_connections (
    route_session_id text NOT NULL,
    route_id text NOT NULL,
    route_version bigint NOT NULL CHECK (route_version >= 1),
    connection_slot smallint NOT NULL CHECK (connection_slot BETWEEN 0 AND 1),
    publisher_connection_id text NOT NULL UNIQUE CHECK (publisher_connection_id <> ''),
    connection_assignment_revision bigint NOT NULL CHECK (connection_assignment_revision >= 1),
    relay_service_id text NOT NULL REFERENCES control.relay_services(relay_service_id) ON DELETE RESTRICT,
    relay_address text NOT NULL CHECK (relay_address <> ''),
    tls_server_name text NOT NULL CHECK (tls_server_name <> ''),
    publisher_connection_credential_digest bytea NOT NULL UNIQUE CHECK (octet_length(publisher_connection_credential_digest) = 32),
    publisher_connection_credential_expires_at timestamptz NOT NULL,
    connected_relay_id text,
    connected_relay_run_id text,
    connected_relay_lease_revision bigint CHECK (connected_relay_lease_revision IS NULL OR connected_relay_lease_revision >= 1),
    claim_id text,
    state text NOT NULL CHECK (state IN ('assigned', 'connected', 'ready', 'draining', 'closed', 'expired')),
    assigned_at timestamptz NOT NULL,
    connected_at timestamptz,
    ready_at timestamptz,
    disconnected_at timestamptz,
    closed_at timestamptz,
    PRIMARY KEY (route_session_id, connection_slot),
    UNIQUE (route_session_id, relay_service_id),
    FOREIGN KEY (route_session_id, route_id, route_version)
        REFERENCES control.route_sessions(id, route_id, route_version) ON DELETE RESTRICT,
    CHECK (publisher_connection_credential_expires_at > assigned_at),
    CHECK (
        (connected_relay_id IS NULL AND connected_relay_run_id IS NULL AND connected_relay_lease_revision IS NULL AND claim_id IS NULL AND connected_at IS NULL) OR
        (connected_relay_id IS NOT NULL AND connected_relay_run_id IS NOT NULL AND connected_relay_lease_revision IS NOT NULL AND claim_id IS NOT NULL AND connected_at IS NOT NULL)
    ),
    CHECK (state <> 'assigned' OR connected_relay_id IS NULL),
    CHECK (state NOT IN ('connected', 'ready', 'draining') OR connected_relay_id IS NOT NULL),
    CHECK (state <> 'ready' OR ready_at IS NOT NULL),
    CHECK (disconnected_at IS NULL OR disconnected_at >= assigned_at),
    CHECK (closed_at IS NULL OR closed_at >= assigned_at)
);

CREATE INDEX route_session_connections_relay_claims
    ON control.route_session_connections (connected_relay_id, connected_relay_run_id, connected_relay_lease_revision)
    WHERE state IN ('connected', 'ready', 'draining');
CREATE INDEX route_session_connections_replacement
    ON control.route_session_connections (route_session_id, connection_slot)
    WHERE state IN ('closed', 'expired');

CREATE TABLE control.ingress_routing_table_clock (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    current_revision bigint NOT NULL DEFAULT 0 CHECK (current_revision >= 0),
    retained_after_revision bigint NOT NULL DEFAULT 0 CHECK (retained_after_revision >= 0),
    updated_at timestamptz NOT NULL,
    CHECK (retained_after_revision <= current_revision)
);

INSERT INTO control.ingress_routing_table_clock (
    singleton,
    current_revision,
    retained_after_revision,
    updated_at
) VALUES (true, 0, 0, now());

CREATE TABLE control.ingress_routing_table_events (
    routing_table_revision bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_kind text NOT NULL CHECK (event_kind IN ('route_upsert', 'route_tombstone', 'challenge_upsert', 'challenge_tombstone')),
    route_id text NOT NULL REFERENCES control.routes(id) ON DELETE RESTRICT,
    route_version bigint NOT NULL CHECK (route_version >= 1),
    canonical_hostname text NOT NULL CHECK (canonical_hostname <> ''),
    entry_revision bigint NOT NULL CHECK (entry_revision >= 1),
    projection bytea NOT NULL,
    route_expires_at timestamptz,
    created_at timestamptz NOT NULL
);

CREATE INDEX ingress_routing_table_events_route
    ON control.ingress_routing_table_events (route_id, route_version, routing_table_revision);
CREATE INDEX ingress_routing_table_events_retention
    ON control.ingress_routing_table_events (created_at, routing_table_revision);

CREATE TABLE control.acme_accounts (
    id text PRIMARY KEY CHECK (id <> ''),
    directory_url text NOT NULL UNIQUE CHECK (directory_url <> ''),
    contact_email text NOT NULL CHECK (contact_email <> ''),
    account_key_ciphertext bytea NOT NULL CHECK (octet_length(account_key_ciphertext) > 29),
    account_key_storage_key_id text NOT NULL CHECK (account_key_storage_key_id <> ''),
    account_url text,
    accepted_terms_url text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at)
);

CREATE TABLE control.control_tls_cache (
    directory_url text NOT NULL CHECK (directory_url <> ''),
    cache_key text NOT NULL CHECK (cache_key <> ''),
    cache_ciphertext bytea NOT NULL CHECK (octet_length(cache_ciphertext) > 29),
    cache_storage_key_id text NOT NULL CHECK (cache_storage_key_id <> ''),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (directory_url, cache_key)
);

CREATE TABLE control.relay_certificate_orders (
    id text PRIMARY KEY CHECK (id <> ''),
    account_id text NOT NULL REFERENCES control.acme_accounts(id) ON DELETE RESTRICT,
    relay_service_id text NOT NULL REFERENCES control.relay_services(relay_service_id) ON DELETE RESTRICT,
    tls_server_name text NOT NULL CHECK (tls_server_name <> ''),
    private_key_ciphertext bytea NOT NULL CHECK (octet_length(private_key_ciphertext) > 29),
    private_key_storage_key_id text NOT NULL CHECK (private_key_storage_key_id <> ''),
    csr_der bytea NOT NULL CHECK (octet_length(csr_der) > 0),
    csr_digest bytea NOT NULL CHECK (octet_length(csr_digest) = 32),
    state text NOT NULL CHECK (state IN (
        'pending', 'authorizing', 'presenting', 'presented', 'validating',
        'ready_to_finalize', 'finalizing', 'cleaning', 'failed_cleaning', 'complete', 'failed'
    )),
    order_revision bigint NOT NULL DEFAULT 1 CHECK (order_revision >= 1),
    order_url text,
    finalize_url text,
    certificate_url text,
    authorization_url text,
    challenge_url text,
    challenge_token text,
    challenge_digest bytea,
    presentation_reference text UNIQUE,
    certificate_pem bytea,
    not_before timestamptz,
    not_after timestamptz,
    renew_at timestamptz,
    work_owner text,
    work_epoch bigint NOT NULL DEFAULT 0 CHECK (work_epoch >= 0),
    work_expires_at timestamptz,
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL,
    last_error text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((work_owner IS NULL) = (work_expires_at IS NULL)),
    CHECK (
        (challenge_url IS NULL AND challenge_token IS NULL AND challenge_digest IS NULL AND presentation_reference IS NULL) OR
        (authorization_url IS NOT NULL AND challenge_url IS NOT NULL AND challenge_token IS NOT NULL AND octet_length(challenge_digest) = 32 AND presentation_reference IS NOT NULL)
    ),
    CHECK (
        (certificate_pem IS NULL AND not_before IS NULL AND not_after IS NULL AND renew_at IS NULL) OR
        (certificate_pem IS NOT NULL AND not_before IS NOT NULL AND not_after IS NOT NULL AND renew_at IS NOT NULL AND not_after > not_before)
    ),
    CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX relay_certificate_orders_active_service
    ON control.relay_certificate_orders (relay_service_id)
    WHERE state NOT IN ('complete', 'failed');
CREATE INDEX relay_certificate_orders_available_work
    ON control.relay_certificate_orders (available_at, id)
    WHERE state NOT IN ('complete', 'failed');

CREATE TABLE control.acme_orders (
    id text PRIMARY KEY CHECK (id <> ''),
    account_id text NOT NULL REFERENCES control.acme_accounts(id) ON DELETE RESTRICT,
    route_session_id text NOT NULL REFERENCES control.route_sessions(id) ON DELETE RESTRICT,
    route_id text NOT NULL REFERENCES control.routes(id) ON DELETE RESTRICT,
    route_version bigint NOT NULL CHECK (route_version >= 1),
    idempotency_key text NOT NULL CHECK (idempotency_key <> ''),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    certificate_cache_key text NOT NULL CHECK (certificate_cache_key <> ''),
    certificate_scope text NOT NULL CHECK (certificate_scope <> ''),
    certificate_identifiers text[] NOT NULL CHECK (cardinality(certificate_identifiers) > 0),
    challenge_method text NOT NULL CHECK (challenge_method IN ('dns-01', 'tls-alpn-01')),
    csr_der bytea NOT NULL CHECK (octet_length(csr_der) > 0),
    csr_digest bytea NOT NULL CHECK (octet_length(csr_digest) = 32),
    state text NOT NULL CHECK (state IN ('pending', 'authorizing', 'ready_to_finalize', 'finalizing', 'waiting_for_install', 'installed', 'failed', 'canceled')),
    order_revision bigint NOT NULL DEFAULT 1 CHECK (order_revision >= 1),
    order_url text,
    finalize_url text,
    certificate_url text,
    certificate_pem bytea,
    not_before timestamptz,
    not_after timestamptz,
    renew_at timestamptz,
    installed_at timestamptz,
    work_owner text,
    work_epoch bigint NOT NULL DEFAULT 0 CHECK (work_epoch >= 0),
    work_expires_at timestamptz,
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL,
    last_error text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (route_session_id, idempotency_key),
    UNIQUE (route_id, route_version, csr_digest, account_id),
    CHECK (array_position(certificate_identifiers, NULL) IS NULL),
    CHECK ((work_owner IS NULL) = (work_expires_at IS NULL)),
    CHECK ((not_before IS NULL) = (not_after IS NULL)),
    CHECK (not_after IS NULL OR not_after > not_before),
    CHECK ((state = 'installed') = (installed_at IS NOT NULL)),
    CHECK (updated_at >= created_at)
);

CREATE INDEX acme_orders_available_work
    ON control.acme_orders (available_at, id)
    WHERE state IN ('pending', 'authorizing', 'ready_to_finalize', 'finalizing', 'waiting_for_install', 'failed', 'canceled');
CREATE INDEX acme_orders_route
    ON control.acme_orders (route_id, route_version, created_at DESC);

CREATE TABLE control.acme_authorizations (
    id text PRIMARY KEY CHECK (id <> ''),
    order_id text NOT NULL REFERENCES control.acme_orders(id) ON DELETE RESTRICT,
    identifier text NOT NULL CHECK (identifier <> ''),
    authorization_url text NOT NULL UNIQUE CHECK (authorization_url <> ''),
    challenge_type text NOT NULL CHECK (challenge_type IN ('dns-01', 'tls-alpn-01')),
    challenge_url text NOT NULL UNIQUE CHECK (challenge_url <> ''),
    challenge_token text NOT NULL CHECK (challenge_token <> ''),
    challenge_digest bytea NOT NULL CHECK (octet_length(challenge_digest) = 32),
    presentation_reference text UNIQUE,
    state text NOT NULL CHECK (state IN ('pending', 'presenting', 'presented', 'validating', 'valid', 'cleaning', 'complete', 'failed', 'canceled')),
    authorization_revision bigint NOT NULL DEFAULT 1 CHECK (authorization_revision >= 1),
    work_owner text,
    work_epoch bigint NOT NULL DEFAULT 0 CHECK (work_epoch >= 0),
    work_expires_at timestamptz,
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL,
    presented_at timestamptz,
    validated_at timestamptz,
    cleanup_completed_at timestamptz,
    expires_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (order_id, identifier),
    CHECK ((work_owner IS NULL) = (work_expires_at IS NULL)),
    CHECK ((challenge_type = 'dns-01') = (presentation_reference IS NOT NULL)),
    CHECK (presentation_reference IS NULL OR presentation_reference <> ''),
    CHECK (updated_at >= created_at),
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX acme_authorizations_available_work
    ON control.acme_authorizations (available_at, id)
    WHERE state NOT IN ('complete', 'canceled');

CREATE TABLE control.route_usage_configuration (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    visitor_network_hash_master_key bytea NOT NULL CHECK (octet_length(visitor_network_hash_master_key) = 32),
    created_at timestamptz NOT NULL
);

CREATE TABLE control.ingress_usage_runs (
    ingress_id text NOT NULL,
    ingress_run_id text NOT NULL,
    ingress_lease_revision bigint NOT NULL CHECK (ingress_lease_revision >= 1),
    started_at timestamptz NOT NULL,
    lease_expires_at timestamptz NOT NULL,
    last_reported_at timestamptz,
    observed_through timestamptz NOT NULL,
    ended_at timestamptz,
    coverage_complete boolean NOT NULL DEFAULT false,
    incomplete_from timestamptz,
    incomplete_until timestamptz,
    PRIMARY KEY (ingress_id, ingress_run_id),
    CHECK (lease_expires_at > started_at),
    CHECK (last_reported_at IS NULL OR last_reported_at >= started_at),
    CHECK (observed_through >= started_at),
    CHECK (ended_at IS NULL OR ended_at >= started_at),
    CHECK (NOT coverage_complete OR ended_at IS NULL OR observed_through >= ended_at),
    CHECK ((incomplete_from IS NULL) = (incomplete_until IS NULL)),
    CHECK (incomplete_until IS NULL OR incomplete_until >= incomplete_from),
    CHECK (coverage_complete OR ended_at IS NULL OR incomplete_from IS NOT NULL)
);

CREATE TABLE control.ingress_usage_reports (
    report_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ingress_id text NOT NULL,
    ingress_run_id text NOT NULL,
    route_id text NOT NULL REFERENCES control.routes(id) ON DELETE RESTRICT,
    route_version bigint NOT NULL CHECK (route_version >= 1),
    bucket_start timestamptz NOT NULL,
    bucket_end timestamptz NOT NULL,
    observed_through timestamptz NOT NULL,
    report_revision bigint NOT NULL CHECK (report_revision >= 1),
    connection_attempts bigint NOT NULL CHECK (connection_attempts >= 0),
    policy_denials bigint NOT NULL CHECK (policy_denials >= 0),
    capacity_denials bigint NOT NULL CHECK (capacity_denials >= 0),
    publisher_open_failures bigint NOT NULL CHECK (publisher_open_failures >= 0),
    successful_streams bigint NOT NULL CHECK (successful_streams >= 0),
    connection_nanoseconds bigint NOT NULL CHECK (connection_nanoseconds >= 0),
    ingress_bytes bigint NOT NULL CHECK (ingress_bytes >= 0),
    egress_bytes bigint NOT NULL CHECK (egress_bytes >= 0),
    histogram_data bytea NOT NULL,
    final boolean NOT NULL DEFAULT false,
    received_at timestamptz NOT NULL,
    FOREIGN KEY (ingress_id, ingress_run_id)
        REFERENCES control.ingress_usage_runs(ingress_id, ingress_run_id) ON DELETE RESTRICT,
    UNIQUE (ingress_id, ingress_run_id, route_id, route_version, bucket_start, report_revision),
    CHECK (bucket_end > bucket_start),
    CHECK (observed_through >= bucket_start AND observed_through <= bucket_end)
);

CREATE INDEX ingress_usage_reports_aggregation
    ON control.ingress_usage_reports (route_id, route_version, bucket_start, report_id);

CREATE TABLE control.route_usage_buckets (
    bucket_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    route_id text NOT NULL REFERENCES control.routes(id) ON DELETE RESTRICT,
    route_version bigint NOT NULL CHECK (route_version >= 1),
    team_id text NOT NULL CHECK (team_id <> ''),
    acting_identity_id text NOT NULL REFERENCES control.identities(id) ON DELETE RESTRICT,
    bucket_start timestamptz NOT NULL,
    bucket_end timestamptz NOT NULL,
    bucket_revision bigint NOT NULL DEFAULT 1 CHECK (bucket_revision >= 1),
    observed_through timestamptz NOT NULL,
    connection_attempts bigint NOT NULL DEFAULT 0 CHECK (connection_attempts >= 0),
    policy_denials bigint NOT NULL DEFAULT 0 CHECK (policy_denials >= 0),
    capacity_denials bigint NOT NULL DEFAULT 0 CHECK (capacity_denials >= 0),
    publisher_open_failures bigint NOT NULL DEFAULT 0 CHECK (publisher_open_failures >= 0),
    successful_streams bigint NOT NULL DEFAULT 0 CHECK (successful_streams >= 0),
    connection_nanoseconds bigint NOT NULL DEFAULT 0 CHECK (connection_nanoseconds >= 0),
    ingress_bytes bigint NOT NULL DEFAULT 0 CHECK (ingress_bytes >= 0),
    egress_bytes bigint NOT NULL DEFAULT 0 CHECK (egress_bytes >= 0),
    histogram_data bytea NOT NULL,
    finalized boolean NOT NULL DEFAULT false,
    complete boolean NOT NULL DEFAULT false,
    finalized_at timestamptz,
    updated_at timestamptz NOT NULL,
    UNIQUE (route_id, route_version, bucket_start),
    CHECK (bucket_end > bucket_start),
    CHECK (observed_through >= bucket_start AND observed_through <= bucket_end),
    CHECK (finalized = (finalized_at IS NOT NULL))
);

CREATE INDEX route_usage_buckets_pending
    ON control.route_usage_buckets (bucket_start, bucket_id)
    WHERE NOT finalized;

CREATE TABLE control.route_usage_deliveries (
    delivery_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    bucket_id bigint NOT NULL REFERENCES control.route_usage_buckets(bucket_id) ON DELETE RESTRICT,
    source_revision bigint NOT NULL CHECK (source_revision >= 1),
    delivery_key text NOT NULL UNIQUE CHECK (delivery_key <> ''),
    state text NOT NULL CHECK (state IN ('pending', 'delivering', 'delivered', 'failed')),
    work_owner text,
    work_epoch bigint NOT NULL DEFAULT 0 CHECK (work_epoch >= 0),
    work_expires_at timestamptz,
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL,
    last_attempted_at timestamptz,
    delivered_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL,
    UNIQUE (bucket_id, source_revision),
    CHECK ((work_owner IS NULL) = (work_expires_at IS NULL)),
    CHECK ((state = 'delivering') = (work_owner IS NOT NULL)),
    CHECK ((attempts = 0) = (last_attempted_at IS NULL)),
    CHECK (last_error IS NULL OR last_error <> ''),
    CHECK ((state = 'failed') = (last_error IS NOT NULL)),
    CHECK ((state = 'delivered') = (delivered_at IS NOT NULL))
);

CREATE INDEX route_usage_deliveries_available
    ON control.route_usage_deliveries (available_at, delivery_id)
    WHERE state <> 'delivered';

CREATE TABLE control.route_recovery_episodes (
    episode_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    route_id text NOT NULL REFERENCES control.routes(id) ON DELETE RESTRICT,
    route_version bigint NOT NULL CHECK (route_version >= 1),
    state text NOT NULL CHECK (state IN ('open', 'observed', 'canceled')),
    opened_at timestamptz NOT NULL,
    observed_at timestamptz,
    canceled_at timestamptz,
    observed_seconds double precision CHECK (observed_seconds IS NULL OR observed_seconds >= 0),
    CHECK (
        (state = 'open' AND observed_at IS NULL AND canceled_at IS NULL AND observed_seconds IS NULL) OR
        (state = 'observed' AND observed_at IS NOT NULL AND canceled_at IS NULL AND observed_seconds IS NOT NULL) OR
        (state = 'canceled' AND observed_at IS NULL AND canceled_at IS NOT NULL AND observed_seconds IS NULL)
    )
);

CREATE UNIQUE INDEX route_recovery_episodes_open
    ON control.route_recovery_episodes (route_id, route_version)
    WHERE state = 'open';

CREATE TABLE control.route_recovery_histogram (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    observation_count bigint NOT NULL DEFAULT 0 CHECK (observation_count >= 0),
    observation_sum_seconds double precision NOT NULL DEFAULT 0 CHECK (observation_sum_seconds >= 0),
    bucket_le_0_25 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_0_25 >= 0),
    bucket_le_0_5 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_0_5 >= 0),
    bucket_le_1 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_1 >= 0),
    bucket_le_2 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_2 >= 0),
    bucket_le_5 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_5 >= 0),
    bucket_le_10 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_10 >= 0),
    bucket_le_20 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_20 >= 0),
    bucket_le_30 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_30 >= 0),
    bucket_le_45 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_45 >= 0),
    bucket_le_60 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_60 >= 0),
    bucket_le_120 bigint NOT NULL DEFAULT 0 CHECK (bucket_le_120 >= 0),
    updated_at timestamptz NOT NULL,
    CHECK (bucket_le_0_25 <= bucket_le_0_5),
    CHECK (bucket_le_0_5 <= bucket_le_1),
    CHECK (bucket_le_1 <= bucket_le_2),
    CHECK (bucket_le_2 <= bucket_le_5),
    CHECK (bucket_le_5 <= bucket_le_10),
    CHECK (bucket_le_10 <= bucket_le_20),
    CHECK (bucket_le_20 <= bucket_le_30),
    CHECK (bucket_le_30 <= bucket_le_45),
    CHECK (bucket_le_45 <= bucket_le_60),
    CHECK (bucket_le_60 <= bucket_le_120),
    CHECK (bucket_le_120 <= observation_count)
);

INSERT INTO control.route_recovery_histogram (singleton, updated_at)
VALUES (true, now());

CREATE TABLE control.maintenance_controls (
    control_name text PRIMARY KEY CHECK (control_name IN ('route_creation', 'route_session_creation', 'certificate_issuance')),
    enabled boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL CHECK (updated_by <> '')
);

INSERT INTO control.maintenance_controls (
    control_name,
    enabled,
    revision,
    updated_at,
    updated_by
) VALUES
    ('route_creation', true, 1, now(), 'system'),
    ('route_session_creation', true, 1, now(), 'system'),
    ('certificate_issuance', true, 1, now(), 'system');

CREATE TABLE control.admin_audit_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_identity_id text REFERENCES control.identities(id) ON DELETE RESTRICT,
    actor text NOT NULL CHECK (actor <> ''),
    request_id text NOT NULL CHECK (request_id <> ''),
    operation text NOT NULL CHECK (operation <> ''),
    target_kind text NOT NULL CHECK (target_kind <> ''),
    target_id text NOT NULL CHECK (target_id <> ''),
    details bytea,
    occurred_at timestamptz NOT NULL,
    UNIQUE (request_id, operation, target_kind, target_id)
);

CREATE INDEX admin_audit_events_occurred_at
    ON control.admin_audit_events (occurred_at DESC, event_id DESC);
