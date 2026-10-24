# signed-human service access

the authority API lets the website manage existing exact-service access without
issuing a human control session. the website credential authenticates the server;
each operation also requires the configured OIDC issuer's signed human assertion.
the actor is resolved by issuer and subject. browser identity IDs, email, and role
claims are not authorization inputs.

## request contract

send the website credential in `Authorization: Bearer …` and the assertion in
`X-Tnl-Actor-Token`. the assertion must target the configured `OIDCClientID`, have
a unique nonempty `jti` (at most 256 bytes), and have `iat` and `exp` within a
five-minute window. use the actual authenticated website session and company
authentication event when asking the issuer to sign; do not sign page-selected
roles or refresh the company authentication timestamp.

the service nonce is unpadded base64url of SHA-256 of these UTF-8 bytes:

```text
tnl.service.actor.v1\n<METHOD>\n<escaped-path[?raw-query]>\n<unpadded-base64url(SHA256(body-bytes))>
```

the newlines above are literal byte `0x0a`, with no trailing newline. uppercase
the HTTP method. hash the exact body bytes sent, including JSON whitespace. GET
and DELETE require no body and hash zero bytes. pagination's raw query is part
of the target; the team is in the path. this purpose is separate from
`tnl.company.actor.v1`. neither assertion authenticates other control operations.

successful reads and writes consume both the exact JWT and issuer/JTI in the
existing assertion exchange table, in the operation's state transaction. failures
roll back consumption with the operation. a retry needs a fresh assertion; keep
the invitation's `Idempotency-Key` and exact body for that operation. an exact
creation retry by the same actor returns HTTP 200 with the original invitation
ID and current state, without its secret. a changed service, normalized email,
or absolute deadline with that key returns `conflict`. current management and
company source authorization are checked before any retry lookup. successful
recovery consumes the fresh assertion too.

only the invitation secret's digest is stored. if the creation response was
lost, explicitly revoke the returned invitation ID, then create with a new key
and deadline. revocation also ends an already accepted invitation's derived
grant; a retry never rotates the secret, revives a revoked invitation, extends
the deadline, or silently creates another invitation. HTTP 201 is the only
response containing a newly created secret. accepted, revoked and expired
invitations remain recoverable as secretless metadata while the actor is still
authorized to manage the service.

the CLI can retain an operation across invocations with an explicit key and
absolute deadline:

```console
tnl share service invite create orders --email=reviewer@example.test --expires-at=2026-10-22T12:00:00Z --idempotency-key=review-42
```

use the same command to recover a lost committed response while the deadline is
still in the future. human output identifies the invitation and gives the revoke
command; JSON returns the same invitation model without `secret`. revoke that ID
with `tnl share service revoke orders <invitation-id>` before creating a replacement
with a new key. `--expires-in` cannot be combined with a caller-supplied key because
it would change the request's deadline on retry.

## generated authority operations

all paths below start with `/v1/service`:

| method and path                                             | operation                         |
| ----------------------------------------------------------- | --------------------------------- |
| `GET /teams/{team_id}/services[?cursor=…]`                  | `listWebsiteServices`             |
| `GET /services/{service_id}`                                | `getWebsiteService`               |
| `GET /services/{service_id}/grants[?cursor=…]`              | `listWebsiteServiceGrants`        |
| `DELETE /services/{service_id}/grants/{grant_id}`           | `revokeWebsiteServiceGrant`       |
| `GET /services/{service_id}/invitations[?cursor=…]`         | `listWebsiteServiceInvitations`   |
| `POST /services/{service_id}/invitations`                   | `inviteWebsiteServiceVisitor`     |
| `DELETE /services/{service_id}/invitations/{invitation_id}` | `revokeWebsiteServiceInvitation`  |
| `POST /service-invitations/preview`                         | `previewWebsiteServiceInvitation` |
| `POST /service-invitations/accept`                          | `acceptWebsiteServiceInvitation`  |
| `GET /services/{service_id}/http-grants`                    | `listWebsiteServiceHTTPGrants`    |
| `POST /services/{service_id}/http-grants`                   | `createWebsiteServiceHTTPGrant`   |
| `DELETE /services/{service_id}/http-grants/{grant_id}`      | `revokeWebsiteServiceHTTPGrant`   |

the OpenAPI authority source references the existing control request and response
schemas. invitation creation uses `{email, expires_at}` and `Idempotency-Key`;
preview and acceptance use only `{secret}`. HTTP creation uses `{kind, expires_at}`.
the explicit deadline remains absolute. invitation acceptance inserts the existing
identity grant with exactly that service and deadline; it creates no membership.
revoking the invitation revokes that accepted grant in the same transaction.

inventory and management recheck current owner/admin membership, disabled identity,
manual suspension, eligibility, and company source/revision/authentication age.
company configuration's disconnected-source recovery exception does not apply.
the typed errors `manager_required`, `source_sign_in_required`, and
`verified_email_required` distinguish actionable failures. invalid, expired,
revoked, accepted, or wrong-recipient invitation secrets return generic
`forbidden` without service details. preview returns only service ID, team ID,
name, protocol, and deadline after matching the secret and issuer-verified email.

service lists/get include existing local or applied project source context.
grant lists return `{grants, next_cursor?}`; invitation lists return
`{invitations, next_cursor?}`. each page has at most 100 records ordered by ID.
the cursor is the last returned grant or invitation ID, exclusive on the next
page, and is absent when no further records were found. both control and
authority use these same control schemas. there is no array-response alias.
each page rechecks current management; authority callers sign the exact cursor
query with a fresh assertion. the CLI follows all pages before emitting a list
or deciding whether a grant ID can be revoked. malformed, overlapping or
nonprogressing pages fail the entire CLI list without partial output.

expired, accepted and revoked records stay in the inventory. callers that filter
history must follow every page before claiming there is no active access. pages
are current reads, not a cross-request snapshot: concurrent changes can alter
later results, so refresh from the first page after mutations. inventory is not
proof of visit permission: an owner/admin can manage without a visitor grant,
and the creator's automatic owner grant still requires current owner/admin
membership. visitor inventory and admission check current grants separately.
HTTP summaries contain only
`subject`, `id`, `kind`, `expires_at`, and optional `revoked_at`, never credentials
or share URLs. native control adds `listServiceHTTPGrants` at
`GET /v1/services/{service_id}/http-grants`; `tnl share service list`
includes those IDs and states under `http_grants` in JSON.

HTTP credential creation retains the existing creator's current visit-access
check as well as current management. a company-session-bound creator still needs
its existing control session to back the credential's later checks. the website
bridge returns `source_sign_in_required` for that case, even with valid company
management proof; it does not mint a session or convert company source proof into
an unbound credential. signed managers can list and revoke existing credentials.

a service HTTP service remains `svc_…`, including public exposure. no service
operation grants permission on a public URL. invitation codes and assertions
belong only in request bodies/headers, never query strings or logs. all bridge
responses are `no-store`. website handlers still own session authentication,
same-origin/CSRF checks, bounded input, and secret delivery.

the website's signed service actor creates the same signed service visitor
credential as the CLI at `POST /v1/service/services/{service_id}/http-grants`.
the request includes the matching service resource; the response separates the
visitor token from its authority-only refresh credential. browser sign-in and
share redemption remain separate operations. the existing service grant list
and revoke endpoints manage these same grant IDs without returning secrets.

## qualification

run `mise exec -- task go:test:integration:service-access` for real PostgreSQL and
configured-issuer HTTP tests. it covers three-page inventories with over 200
records and revoked/expired history, lost committed response recovery, changed
request conflicts, explicit CLI revoke/reissue, exact request binding, JWT/JTI replay,
website-only rejection, current roles and company sources, disabled identities,
issuer-verified recipient email, preview without acceptance, exact grant/deadline
and revocation lifecycle, service HTTP inventory and resource-scope rejection.
