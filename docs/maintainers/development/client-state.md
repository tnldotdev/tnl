# client state boundaries

The native client opens `v1.db` inside its selected state directory. This is a
fresh SQLite baseline: it does not open or import earlier client databases.
The macOS Keychain service for locally protected values has its own v1 name;
other platforms use a private `v1.wrapping-key` file. Every database checks
its `state_protection` row against the selected key on open.
The Go application code reads and writes through `internal/client/state`; edit
the migration and query sources before regenerating `clientstatedb`.

## follow the local owner

```text
server_profiles
  ├── control_sessions / guest_demo_sessions
  └── pending_publisher_enrollments → publisher_identities → publisher_selections

local_tunnels → project_journals → project_events
      │           project_url_inventory
      ├── oauth_pending_callbacks / webhook_declarations
      └── alias_declarations / alias_publish_runs

inspections → inspection_number_counters / inspection_storage_usage

identities/ (or --identity-dir)
  ├── replica signing identities and selector records
  └── control/team/publisher/plan-scoped pending and current certificate files
```

`installation_settings` and `state_protection` each have one row. The
root-owned system publisher stores its encrypted registry and file manifest in
separate tables. Project journal rows hold the latest app-service snapshot and
one cursor epoch; local tunnel triggers add publication events in the same
SQLite transaction. Events retain at most 2,048 entries and 8 MiB per project.

Project paths identify local worktrees. A `public_url_id`, team ID, or publish
run number names server state, not a local foreign key. Inspection rows can
outlive a pruned tunnel, so their tunnel ID is historical rather than an FK.
SQLite timestamps are Unix nanoseconds except for explicitly suffixed values
such as `duration_ms`.

## keep secrets and retries separate

the filesystem identity owner stores publisher TLS keys, pending CSRs and
staged/current certificates in bounded mode-0600 files under owner-only
directories. local and deployed publishers use this same cache. atomic replace
and file/directory sync precede external issuance or installation; certificate
and replica locks live on that same filesystem. runtime SQLite and its wrapping
key can be replaced while preserving this directory. Fargate mounts only the
durable identity directory on EFS and keeps SQLite local.

group signing identities also live in that durable directory. bootstrap input
is verified with control before retention or import into the runtime cache.
installed group jobs load their signing key directly from the identity files.
filesystem permissions and the storage platform's encryption/backup policy
protect these files independently of SQLite's local secret protector.

Protected publisher signing keys are saved once per server and identity;
selections point to that installed identity. A pending enrollment holds the
same key across a lost redemption response and may hold a protected one-use
enrollment secret while that retry is possible. Identity promotion commits the
installed key, its selection, and an expiring enrollment-secret digest binding
together; repeated enrollment never creates a second signing key. Job-registry
documents stay encrypted as whole values; their file manifest is checked on
restart.

`telemetry_enabled` and `refresh_pending` are genuine SQLite booleans, stored
as integers constrained to 0 or 1. An OAuth alias handoff uses `consumed_at`
instead of a boolean: retain the consumed row until expiration so replay cannot
fall through to a replacement publish run.
