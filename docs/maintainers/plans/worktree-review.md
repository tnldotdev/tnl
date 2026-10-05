# worktree review

Audience: tnl maintainers. This is the planned worktree sharing and feedback
workflow.

## the result

Run `tnl dev` to publish the configured services in one Git worktree. Send a
reviewer one link to that worktree preview. The reviewer can use the app and
leave pinned feedback. The developer or a local coding agent can inspect the
report, address it in the right checkout, and ask for a recheck.

A worktree preview groups saved public URLs; each public URL still owns its
hostname, visitor policy, and publish runs. A feedback thread is a durable
record containing an immutable report, a small evidence bundle, and ordered
follow-up events. The toolbar and CLI read the same record.

## configure services and addresses

One project configuration selects one server and team. `tnl dev` starts the
configured services together and identifies the service blocking readiness or
causing the tunnel to stop. Each service keeps its own public URL. A service
can also mount another local service at a path on its public URL:

```ts
export default defineConfig({
  server: "https://control.example.com",
  team: "studio",
  feedback: true,
  services: {
    web: {
      dev: { command: ["vite", "dev"] },
      paths: { "/api": "api" },
    },
    api: {
      dev: { command: ["node", "server.js"] },
    },
  },
});
```

The API remains available at its own hostname and at `web`'s `/api` path. The
publisher matches complete path segments and preserves the requested path by
default. An object mount can set `stripPrefix: true`. The visitor policy of
the public URL reached by the browser applies to its mounted paths. Ingress
selects the public URL by hostname; the publisher selects the local service
after terminating visitor TLS. Reserve `/__tnl/` for publisher-served review
pages, assets, and requests.

Control assigns a `worktree_preview_id` and records its authorized public URL
IDs. Store the group ID in client state for later runs of the same checkout;
validate group membership against the selected server, team, and public URL
ownership. `.tnl/project.json` continues to describe worktree-specific
service hostnames and URLs and expands to describe path mounts. `tnl init`
writes project-level `feedback: true` into new configurations.

## share a worktree preview

```text
tnl share create
tnl share create web.example.com --expires-in 7d
tnl share list
tnl share list web.example.com
tnl share revoke SHARE_ID
```

Create captures the IDs of all public URLs configured for the worktree at
that time. The optional argument selects the page the link opens; it accepts
a public URL ID, bare hostname, or HTTPS origin. With one unambiguous page,
create can select it from the current project. A newly configured public URL
gets a new link. A new path on an included public URL follows that URL's
access. List without a selector shows manageable shares in the selected team;
an optional URL filters to its worktree preview.

Create prints the complete link and a newline on stdout. List and revoke use
the shared CLI renderer. The CLI generates a high-entropy secret; control
stores its fingerprint, the included public URL IDs, creator, and expiry.
Links expire after 24 hours by default, accept day shorthand, and support an
explicit longer lifetime up to 30 days.

The link opens at `/__tnl/share/<share-id>.<secret>` on the selected hostname.
Redemption establishes a separate, host-only `__Host-tnl-share` cookie on each
included active hostname using short-lived handoffs. Reopening the link can
establish access when another included hostname starts later. Publishers
check the grant before forwarding requests and remove tnl's cookie before
sending requests to local services. App cookies pass through. An allowed IP
continues to visit without a link.

Ingress gives visitors outside the IP allowlist bounded forwarding for a
sharing-enabled public URL. Publishers refresh grant state on heartbeats,
check expiry on new requests, and fail closed for link access when the last
confirmed grant state becomes stale. Revocation rejects new requests within
roughly 30 seconds; established streams finish normally. Require a
share-capable publisher before enabling sharing on its public URL.

Apps that call another service hostname from the browser use their normal
cross-origin credential and CORS settings. A path mount provides a
same-origin address for browser calls when that matches the app's setup.

## store feedback as reports and events

Each thread stores `worktree_preview_id`, the exact `public_url_id`, the page
path, service, and publish run number where the report was made. Its original
report contains the reviewer's text, creation time, and optional unverified
display name. The selected element and submitted context belong to that
immutable report. A page-level report uses `element.kind: "page"`.

At submission, the local publisher records `checkout_at_report`: the Git
`HEAD` commit, branch, changed project-relative file paths and statuses,
per-file content SHA-256 identifiers, and a fingerprint of the combined
checkout state. Bound the file list and fingerprint work; mark a partial
marker so a later comparison can distinguish it from a complete match. A
publish run number identifies the tunnel lifecycle. The checkout marker
identifies the local code state recorded with the report.

Replies, context requests, added evidence, fixes, rechecks, and resolution
are timestamped events appended to the thread. Fix and recheck events carry
their own checkout markers. The current state is projected from the event
history:

```text
open -> ready_for_recheck -> resolved
             |
             +-- still broken -> open
```

A reviewer with share access can reply, answer a context request, and report
a failed recheck. An identity authorized to manage the public URL marks a
thread ready for recheck or resolved. Member-owned public URL feedback belongs
to that member; team-shared public URL feedback is managed by admins and
owners. Reviewers with valid worktree access see shared threads on the
included public URLs.

Creating a report appends a `thread.created` event in the same transaction.
Control assigns ordered, durable cursors to feedback events. The CLI can
read a snapshot and resume events after its last cursor without losing a
reply across a reconnect. Writes use idempotency keys so retried requests
append each event once.

## show feedback on the page

When feedback is enabled, the publisher injects a small script reference
into eligible `tnl dev` HTML responses and serves the toolbar under
`/__tnl/`. Build the toolbar as tested TypeScript/TSX components, bundle its
versioned assets into `tnl`, and mount its UI in a Shadow DOM root. Handle
streaming HTML, response encoding, caching headers, and the page's content
security policy at the publisher boundary.

Reviewers can pin comments, read shared threads, and reply. Pins track an
element while it matches confidently; threads with changed or missing
elements remain in the page inbox with their original context. The local
tunnel owner opens review and resolution controls through a short-lived local
handoff.

The toolbar keeps a short, in-browser trail of semantic clicks, submits,
and navigations. At submission it prepares a bounded, sanitized HTML excerpt
around the selected element, including its role, label, and useful
identifiers. The publisher keeps a short per-browser trail of failed request
methods, paths, statuses, and durations. The reviewer sees the evidence
bundle before posting it. Control retains the submitted bundle with the
immutable report.

## let an agent inspect and follow up

```text
tnl feedback list --output=json
tnl feedback inspect FEEDBACK_ID --output=json
tnl feedback watch --after CURSOR --output=ndjson
tnl feedback reply FEEDBACK_ID --message "..."
tnl feedback ready FEEDBACK_ID --message "..."
tnl feedback resolve FEEDBACK_ID
```

List and inspect work after the tunnel stops. Inspect returns the durable
thread and adds `local_worktree` from the developer's machine: its path,
whether it matches the preview, and whether its current checkout matches
the report marker. Control stores project-relative changed-file identifiers
and checkout fingerprints; the CLI resolves the local path.

For example, a ready-for-recheck thread can produce this JSON shape. The
original report stays in place when the fix event is appended:

```json
{
  "schema_version": 1,
  "id": "fb_123",
  "state": "ready_for_recheck",
  "scope": {
    "worktree_preview_id": "preview_456",
    "public_url_id": "url_789",
    "publish_run_number": 12,
    "page_path": "/settings/profile",
    "service": "web"
  },
  "report": {
    "text": "Save says it worked, but my changes disappear after reload.",
    "author": { "display_name": "Sam", "verified": false },
    "created_at": "2026-10-04T14:32:18Z"
  },
  "element": {
    "kind": "element",
    "role": "button",
    "label": "Save changes",
    "test_id": "save-profile",
    "html": "<button data-testid=\"save-profile\">Save changes</button>"
  },
  "context": {
    "actions": [
      { "type": "navigation", "path": "/settings/profile" },
      { "type": "click", "label": "Save changes", "test_id": "save-profile" }
    ],
    "failed_requests": [
      { "method": "POST", "path": "/api/profile", "status": 500, "duration_ms": 184 }
    ]
  },
  "checkout_at_report": {
    "head_commit": "0123456789abcdef0123456789abcdef01234567",
    "branch": "perf",
    "changed_files": [
      {
        "path": "apps/web/src/ProfileForm.tsx",
        "status": "modified",
        "content_sha256": "sha256:..."
      }
    ],
    "fingerprint": "sha256:...",
    "complete": true
  },
  "events": [
    {
      "cursor": 40,
      "type": "thread.created",
      "at": "2026-10-04T14:32:18Z"
    },
    {
      "cursor": 41,
      "type": "fix.ready_for_recheck",
      "at": "2026-10-04T14:40:00Z",
      "text": "Updated the save handler; please try again.",
      "checkout": {
        "head_commit": "0123456789abcdef0123456789abcdef01234567",
        "fingerprint": "sha256:..."
      }
    }
  ],
  "local_worktree": {
    "path": "/Users/alex/git/shop-perf",
    "matches_preview": true,
    "matches_report_checkout": false
  }
}
```

An agent uses the page, element HTML, actions, failed requests, and checkout
comparison to search and verify the relevant code. It records a fix as an
event, reads the recheck, and resolves the thread through an explicit command.
The toolbar and CLI project the same state and event history.

## own the boundaries

Control owns worktree preview membership, grants, feedback threads, event
cursors, and authorization in PostgreSQL. Extend the control, authority, and
ingress OpenAPI sources for their respective operations and projections. The
built-in authority and hosted external authority both check the existing
member-owned and team-shared public URL permissions before group membership,
grant, or feedback mutations. Ingress receives the information it needs to
admit sharing-enabled visitors; the publisher receives grant state through
authenticated publish-run operations.

Add `share.create` and `feedback.manage` to the authority contract before
control sends either operation to an external authority. Deploy the hosted
authority with both operations before switching hosted control from its
existing `public_url.update` check; both decisions retain the public URL's
ownership and mutation-revision binding.

The publisher owns visitor HTTP access checks, local path dispatch, browser
redemption and feedback endpoints, HTML injection, and the bounded per-browser
failed-request trail. The toolbar sends submitted feedback through the
publisher; the authenticated CLI reads and manages the same control records.
Keep local worktree paths and source bytes on the developer's machine. Build
the toolbar bundle reproducibly and include its dependencies' legal files in
the client release artifacts.

## build and verify in stages

1. Add project-level server and team validation, coordinated `tnl dev`
   services, durable worktree preview grouping, path mounts, and expanded
   project metadata. Update `tnl init` to emit `feedback: true`.
2. Add grant tables and control and authority contracts, share commands,
   multi-host redemption, ingress admission, and publisher access checks.
3. Add immutable feedback reports, bounded evidence, ordered events, state
   projections, checkout markers, and member and team-shared authorization.
4. Bundle and embed the toolbar, inject it at the publisher, add the owner
   handoff and agent CLI, and expose resumable event reads.
5. Verify path matching and streaming, worktree ownership, share membership
   and revocation, HTML injection in Next and Vite, dynamic pins, evidence
   bounds, checkout comparison, event ordering and resume, and hosted and
   self-hosted authorization. Update the public development and CLI guides
   in `tnl.dev` as each stage lands.

Edit OpenAPI, migration, and query sources before regenerating committed
code. Use the repository's [validation sequence](../../../contributing.md#check-your-change)
for the implementation stages.
