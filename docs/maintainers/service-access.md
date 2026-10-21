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
the invitation's `Idempotency-Key` and exact body for that operation. the existing
invitation transaction rejects a used creation key with `conflict` and never
returns a stored secret.

## generated authority operations

all paths below start with `/v1/service`:

| method and path                                                             | operation                                |
| --------------------------------------------------------------------------- | ---------------------------------------- |
| `GET /teams/{team_id}/private-services[?cursor=…]`                          | `listWebsitePrivateServices`             |
| `GET /private-services/{private_service_id}`                                | `getWebsitePrivateService`               |
| `GET /private-services/{private_service_id}/grants`                         | `listWebsitePrivateServiceGrants`        |
| `DELETE /private-services/{private_service_id}/grants/{grant_id}`           | `revokeWebsitePrivateServiceGrant`       |
| `GET /private-services/{private_service_id}/invitations`                    | `listWebsitePrivateServiceInvitations`   |
| `POST /private-services/{private_service_id}/invitations`                   | `inviteWebsitePrivateServiceVisitor`     |
| `DELETE /private-services/{private_service_id}/invitations/{invitation_id}` | `revokeWebsitePrivateServiceInvitation`  |
| `POST /private-service-invitations/preview`                                 | `previewWebsitePrivateServiceInvitation` |
| `POST /private-service-invitations/accept`                                  | `acceptWebsitePrivateServiceInvitation`  |
| `GET /private-services/{private_service_id}/http-grants`                    | `listWebsiteManagedHTTPGrants`           |
| `POST /private-services/{private_service_id}/http-grants`                   | `createWebsiteManagedHTTPGrant`          |
| `DELETE /private-services/{private_service_id}/http-grants/{grant_id}`      | `revokeWebsiteManagedHTTPGrant`          |

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
grants and invitation lists retain the existing 101-record bound; expired and
revoked records are history, not current access. HTTP summaries contain only
`subject`, `id`, `kind`, `expires_at`, and optional `revoked_at`, never credentials
or share URLs. native control adds `listManagedHTTPGrants` at
`GET /v1/private-services/{private_service_id}/http-grants`; `tnl share service list`
includes those IDs and states under `http_grants` in JSON.

HTTP credential creation retains the existing creator's current visit-access
check as well as current management. a company-session-bound creator still needs
its existing control session to back the credential's later checks. the website
bridge returns `source_sign_in_required` for that case, even with valid company
management proof; it does not mint a session or convert company source proof into
an unbound credential. signed managers can list and revoke existing credentials.

a managed HTTP service remains `psvc_…`, including public exposure. no service
operation grants permission on a public URL. invitation codes and assertions
belong only in request bodies/headers, never query strings or logs. all bridge
responses are `no-store`. website handlers still own session authentication,
same-origin/CSRF checks, bounded input, and secret delivery.

## qualification

run `mise exec -- task go:test:integration:service-access` for real PostgreSQL and
configured-issuer HTTP tests. it covers exact request binding, JWT/JTI replay,
website-only rejection, current roles and company sources, disabled identities,
issuer-verified recipient email, preview without acceptance, exact grant/deadline
and revocation lifecycle, managed HTTP inventory and resource-scope rejection.
no database schema or tunnel protocol change is needed.
