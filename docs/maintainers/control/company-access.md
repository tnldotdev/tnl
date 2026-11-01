# company access boundaries

control owns connections, admission requests, membership roles and manual
decisions, company session proofs, and publisher subjects. tnl.dev owns provider
configuration, consent, source authentication, and directory APIs. control stores
an opaque `source_id`; it does not interpret Google, Entra, or GitHub settings.

the source contract is `api/control/authority/v1/openapi.yaml`. its generated clients and
server operations are implemented by control. there is no snapshot bridge,
arbitrary service actor, immediate-active creation, or general lifecycle setter.

## owner website operations

every `/v1/service/teams/...` company operation requires both:

- `Authorization: Bearer <website credential>`;
- `X-Tnl-Actor-Token: <fresh configured-issuer OIDC ID token>`.

the actor token must use control's configured OIDC audience, expire within five
minutes, and carry the exact operation nonce below. control resolves `(iss, sub)`
to its stored identity and checks its **current** nonremoved, non-manually-
suspended owner membership inside the mutation transaction. issuer roles, email
domains, `actor_user_id`, and provisioning credentials cannot grant ownership.
active-company owners also need current company authentication unless control
has explicitly granted a personal-account exception. each committed operation
consumes the assertion digest once. issue a new unique ID token for each call.

compute the standard OIDC `nonce` from the bytes actually sent:

```text
body_digest = base64url_no_padding(SHA256(request_body_bytes))
nonce = base64url_no_padding(SHA256(UTF8(
  "tnl.company.actor.v1\n" + METHOD + "\n" + request_target + "\n" + body_digest
)))
```

use uppercase HTTP methods and an empty body for GET. `request_target` is the
escaped path plus the exact `?query` when present, without an origin.
`controlstate.CompanyActorNonce` implements this formula. serialize
the body once, request the issuer token with this nonce, then send those same
bytes. do not accept a caller's asserted actor or construct company provenance
from linked-account metadata.

| generated operation              | path and behavior                                                                                                                                                                                                                           |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `readCompanyConnections`         | `GET /v1/service/teams/{team_id}/identity-connections`; returns optional `active` and `setup` objects, never capabilities                                                                                                                   |
| `beginIdentityConnectionSetup`   | `POST` to that path with `source_id`, `admission`, and optional `replace_id` / `expected_revision`; returns pending `icn_...`, revision, `setup_token`, and 15-minute expiry                                                                |
| `activateIdentityConnection`     | `POST .../{identity_connection_id}/activate` with required `expected_revision`, `setup_token` and `provisioning_token`; requires signed tenant/source proof and current ownership; returns the advanced active revision and that credential |
| `disconnectIdentityConnection`   | `DELETE .../{identity_connection_id}` with `expected_revision`; aborts pending setup or retires an active source and fences old work                                                                                                        |
| `rotateCompanyProvisioningToken` | `POST .../{identity_connection_id}/provisioning-token` with `expected_revision`; explicitly revokes the old token and issues a new one under fresh current owner proof; never use as an activation retry                                    |
| `listCompanyAdmissions`          | `GET /v1/service/teams/{team_id}/company-admissions`                                                                                                                                                                                        |
| `decideCompanyAdmission`         | `POST .../company-admissions/{request_id}` with current `connection_revision` and `decision: approved` or `denied`                                                                                                                          |
| `setCompanyMembershipDecision`   | `PUT /v1/service/teams/{team_id}/memberships/{membership_id}/company-decision` with `suspended` and `personal_account_exception`                                                                                                            |
| `setCompanyInvitationException`  | `PUT /v1/service/teams/{team_id}/invitations/{invitation_id}/company-decision` with `personal_account_exception`; pending invitations only                                                                                                  |

an owner may explicitly grant a contractor invitation or membership exception.
it permits personal-account sign-in, but does not clear manual suspension or
removal. sync cannot change that decision or assign admin/owner roles.

`listCompanyAdmissions` returns `{requests, next_cursor?}` with at most 100 rows.
it includes complete history: pending and decided requests, including previous
source revisions. follow `?cursor=<next_cursor>` until the cursor is absent.
order is ascending `created_at`, then bytewise `request_id`; each cursor must
identify a request in the selected team. sign each page's complete request
target with a fresh actor assertion. a first-page assertion cannot authorize a
different cursor. decisions still require the current source revision.

## consent before enforcement

setup creates a pending connection without changing the active source, team
policy, existing eligibility, memberships, URLs, or runs. a replacement keeps
the old source active. failed consent, failed verification, expiry, or explicit
abort cannot retire that source or lock out the setup owner.

after provider consent succeeds, stage the owner's exact directory eligibility
using `setup_token` and the pending revision. activation requires an issuer-
signed team-context record for that pending connection/source/revision and the
same owner's directory subject. the staged owner must be eligible, unless that
owner already has an explicit control-owned contractor exception. both current
ownership and the capability are checked again. activation atomically retires
the replaced source, advances the new revision, promotes staged eligibility to
that revision, enables company enforcement, and issues a different provisioning
credential. the setup credential cannot provision eligibility afterward.

the activation body requires a random 256-bit `provisioning_token` encoded as
43 canonical base64url characters. the caller must encrypt and persist it before
sending activation. retries with the same setup capability, expected revision and
credential return that same active connection only while the credential's digest
is still current. they recheck current owner/source authorization and never rotate
a token, advance the revision again, or replay activation's policy changes. a late
retry after explicit token rotation cannot restore the old credential. when local
eligibility expired after a lost reply, the precommitted credential can first
submit a fresh owner delta at the active revision, then the fresh owner proof can
read the authoritative connection. missing, empty and invalid credentials are
rejected; activation never generates a provisioning credential. no recoverable
plaintext secret is stored by control.

staging never creates managed memberships. send subsequent per-user deltas at
the active revision with higher per-user revisions to perform managed admission.
other old-source managed memberships require an explicit owner approval to bind
them to the new source. activation can rebind the consenting owner only; roles,
membership IDs, slugs and manual decisions remain control-owned.
that bootstrap binding names the already-authorized owner membership and identity
and records both the membership ID and previous connection in the activation
audit. the owner can then authenticate to the new source before approving any
other membership rebind.

disconnect deliberately does not restore old-source access. a fresh scoped OIDC
owner proof can read and reconfigure disconnected settings, while ordinary team,
visitor and publishing operations remain denied for suspended members. explicit
audited owner/admin recovery is also available through
`POST /v1/company-access/recovery`; no built-in login bypass exists in the active
membership predicates.

## account mapping and per-user deltas

`POST /v1/service/identity-context` resolves the website's verified OIDC `sub`
(including UUID subjects) under the configured issuer and returns the actual
control identity ID. it is identity metadata, not owner authorization.
nonremoved suspended memberships remain visible with `active: false`, so an
owner can still select disconnected settings. ordinary authorization always
rechecks the shared active predicates and verified company session.

`provisionCompanyEligibility`, `POST /v1/service/company-eligibility`, requires
the website credential and `X-Tnl-Provisioning-Token`. its exact body is:

```json
{
  "team_id": "team_...",
  "identity_connection_id": "icn_...",
  "connection_revision": 2,
  "account_subject": "website-oidc-sub-uuid",
  "subject": "immutable-directory-subject",
  "revision": 3,
  "eligible": true,
  "valid_until": "2026-10-18T23:30:00Z",
  "member_slug": "sam"
}
```

control resolves `account_subject` itself. `subject` is a separate directory
identifier, never an email or inferred account link. unknown OIDC accounts must
first be resolved through the identity operation using verified website account
facts. directory entries without a verified account mapping cannot be provisioned.

a new active source may record correctly scoped eligibility while a membership
is still bound to the retired source, including for manually suspended or
removed members. this only records directory facts: it does not move the
membership, assign a role, clear a manual decision, or restore a tombstone.
an eligible nonremoved person can sign in to the new source and request a
rebind; even managed admission leaves an old-source membership pending until a
current owner explicitly approves it. approval preserves its existing role and
manual decisions. a removed membership remains ineligible for admission.

the connection credential cannot provision another team or source. revisions
increase per identity; equal revisions require identical content. eligibility
has a maximum 24-hour freshness window. missing entries never remove anyone.
renewal of already-current eligibility is audited without disconnecting healthy
visitors. loss, shorter validity, and expiration advance policy and revoke access.

website scans stay website-local. only a completed scan may produce negative
deltas for previously mapped subjects. persist the exact per-user revision and
payload before sending, and retry the same payload after an uncertain response.
partial scans must not emit removals. there is no control replace-all operation.

a globally disabled account can receive `eligible: false` deltas, including exact
retries. positive deltas and normal account resolution still reject it; directory
sync cannot reactivate an identity. this negative-only path avoids aborting an
entire completed roster when a former eligible account was globally disabled.

## one company claim and control login intent

the configured issuer signs **one** generic `tnl_team_contexts` contract:

```json
{
  "iss": "https://configured-issuer.example",
  "sub": "website-account-uuid",
  "aud": "configured-control-client",
  "nonce": "control-intent-nonce-or-operation-nonce",
  "tnl_team_contexts": [
    {
      "team_id": "team_...",
      "identity_connection_id": "icn_...",
      "connection_revision": 2,
      "source_id": "immutable-website-source-record-id",
      "subject": "immutable-directory-subject",
      "authenticated_at": 1792364400
    }
  ]
}
```

`source_id` binds the actual verified provider/tenant/selection event to the
opaque source selected at setup. `authenticated_at` is the actual company
authentication time, not refresh time. the array may contain old and pending
connections for one team during replacement consent. a browser login accepts
exactly its selected current connection; other-team proofs can only be copied
from a prior same-identity control session while still current, with their
original authentication deadlines.

the implemented login operations are:

1. `createCompanyLoginIntent`: `POST /v1/auth/company-intents`, `{team_id}`.
   control selects the exact active connection/revision/source and configured
   issuer/client, and fixes the redirect to its `/v1/auth/device/callback`.
   the response includes a ten-minute `intent_id`, `nonce`, `binding_token`,
   `client_id`, `redirect_uri`, and source scope.
2. `resolveCompanyLoginIntent`: `POST .../{intent_id}/resolve`, `{binding_token}`.
   the issuer/control browser handler reads the bound selection. replaced,
   retired, expired, consumed, or wrongly bound intents fail closed.
3. `startDeviceLogin`: `POST /v1/auth/device`, `{team,refresh_token?}` starts
   browser approval; `team` is an exact name or immutable ID. Control redeems the
   code at `/v1/auth/device/callback` and confirms the human code before issuing
   a session. The CLI uses `/v1/auth/device/poll` with its private
   `{polling_credential}`. The nonce, actual audience, callback, selected team,
   connection revision, source, account identity and eligibility must all match.

the browser/device handler stores `CompanyIntentBinding` with its encrypted
device attempt, separately from the device polling credential and browser
state/PKCE binding. use the intent nonce in the OIDC authorization request and
pass the resolved source selection to the issuer. the trusted issuer may receive
the intent ID/binding over its authenticated server path; do not expose the
device polling credential. redemption verifies the ordinary state, browser
cookie, PKCE and OIDC nonce, then supplies the persisted intent binding alongside
the verified `oidcauth.Identity` fields to `OIDCIdentity`. user approval creates
the session through the same assertion- and intent-consuming transaction.

`storeVerifiedCompanyContexts` is the implemented transaction boundary using
generated queries. it takes `Queries`, not a separately committed adapter.
`TeamContexts`, `Nonce`, `ClientID` and `CompanyIntent` are the concrete inputs.
the single persisted contract is `control.company_session_contexts`; browser and
device callbacks use it directly inside the session transaction.

ID-token expiry gates exchange only. derived company proof lasts until the
original authentication time plus one hour, bounded by control refresh expiry
and current eligibility. `company_authentication_expires_at` exposes that fixed
deadline. refresh retains it and rejects expired/revoked company context instead
of silently issuing a session with unauthenticated company access. another
company authentication requires another control intent.

## website workstream mapping

replace the custom `features/company/control-contract.server.ts` bridge with
the generated operations above:

- `connection_id: UUID` becomes control's `identity_connection_id: icn_...`;
  response `revision` becomes delta/claim `connection_revision`. never generate
  a control connection ID in the website.
- keep provider configuration in the website's `source`; assign a new immutable
  opaque `source_id` to each consent configuration and use that exact value in
  verified issuer claims. no vendor data or directory client moves into control.
- `beginSetup` / `activate` / `disable` map to setup / activation / disconnect.
  activation advances the revision; it does not return the pending revision.
  setup and provisioning capabilities are different credentials.
  a new connection starts at revision 1. replacement names the currently active
  ID/revision; with no active source, omit replacement fields even if a retired
  record has a larger revision. remove the website's cross-connection revision
  comparison and background worker activation: consent activation needs the
  current owner's operation-bound proof, not an asserted stored actor ID.
- `reconcile(snapshot)` becomes durable per-account deltas after a complete
  website scan. `snapshot.sequence` may serve as a monotonic per-user revision;
  after activation it must advance beyond staged revisions.
- `requestAccess` uses the real company control session and
  `requestCompanyAdmission`; request IDs are control `caq_...` IDs. `decide`
  uses owner proof and `decideCompanyAdmission`. remove website-local admission
  authority, `admitMember` role payloads, and provisioning-token approval.
- `contractor` chooses the invitation or membership generated operation with
  current owner proof. an accepted invitation is managed through its membership.
- `runtime.server.ts` calls these concrete operations. its unbound bridge and
  authentication-reader setters are not an authorization source. the issuer
  constructs the single signed claim only from its verified source event.

## revocation and unattended publishers

active membership/subject predicates combine current identity/team state,
independent manual decisions, exact connection provenance and fresh eligibility.
known approval-mode company subjects require company sign-in for identity grants
even before admission. sync never resurrects a removal tombstone or resets roles.

publisher records explicitly store team/member/guest ownership. member-owned
credentials and public/private runs stop on offboarding. team-owned identities
and groups continue independently of their creator; that person is audit history.
connector peer pairs and mTLS certificates retain their issuing control
session for live checks. public heartbeats fence visitor caches and in-flight
decisions and close existing streams, including HTTP upgrades, on policy changes.
other visitors reconnect conservatively; publisher runs remain available.
