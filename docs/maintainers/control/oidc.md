# human authentication

Control is the OIDC client. The CLI only starts a login with control, shows
control's approval URL and code, and polls control with a private credential.
No provider device grant, CLI provider client, loopback callback, login token,
shared administrator identity, or first-user administrator exists.

## configure a provider

Register a web/server client with these exact redirect URLs, replacing the origin:

```text
https://control.example.com/v1/auth/device/callback
https://control.example.com/v1/browser/callback
```

Configure `TNLD_OIDC_ISSUER`, `TNLD_OIDC_CLIENT_ID`, and, for confidential clients,
`TNLD_OIDC_CLIENT_SECRET`. `TNLD_OIDC_SCOPES=openid,profile,email` requests useful
display claims. Control always uses authorization code with S256 PKCE. A provider
must advertise standard discovery, authorization and token endpoints, and an
HTTPS JWKS endpoint with RS256 keys. Back-channel redirects are rejected; response
bodies, tokens, request durations, and token lifetimes have bounds.

Control selects `client_secret_post` or `client_secret_basic` from discovery.
Missing authentication-method metadata defaults to Basic, as OIDC specifies.
It does not probe methods by retrying a one-use authorization code.

| provider                        | issuer and client registration                                                                                                                                                                                                |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| generic OIDC                    | use the exact issuer in discovery and a code/PKCE server client; a secret is optional for a public PKCE client                                                                                                                |
| direct Google                   | `https://accounts.google.com`; create a web application OAuth client, supply its secret, and register both redirect URLs                                                                                                      |
| tenant-specific Microsoft Entra | `https://login.microsoftonline.com/<tenant-id>/v2.0`; register a single-tenant web application with both redirect URLs and a client secret; do not use `common` or `organizations` as the issuer                              |
| hosted tnl                      | use the exact configured issuer at `account.tnl.dev`, including its trailing slash if present, and a server client registered with the hosted broker; upstream GitHub, Google, and Microsoft selection belongs to that broker |
| GitHub                          | use an OIDC broker; GitHub's OAuth login is not an OIDC discovery/ID-token provider                                                                                                                                           |

The provider-profile tests exercise these standard wire shapes offline, including
tenant-path discovery, client-secret-post, default client-secret-basic,
public-client PKCE, nonce, audience,
issuer, signature, and key fetching. They do not claim live account or tenant
qualification. Entra email claims are not treated as verified email merely
because they are present. Identity and privilege are keyed by exact issuer and
subject, never email or display name.

Self-hosted control talks directly to its configured provider. It does not need
the hosted website. Publisher identities, device keys, enrollment keys, and
visitor-scoped credentials retain their separate authentication boundaries.

## seed named identities once

```text
TNLD_OIDC_ISSUER=https://identity.example.com
TNLD_INITIAL_ADMINISTRATORS=operator-subject
TNLD_INITIAL_TEAM_OWNERS=studio=owner-subject
TNLD_DEFAULT_TEAM=studio
TNLD_DEFAULT_TEAM_MEMBERS=member-subject,owner-subject
```

Each subject above is qualified by the exact configured issuer. Administrators
are server administrators; organization owners are explicit team owners. Default
team membership is limited to the explicitly eligible subjects. Control records
each privilege seed once. Restarting with the same configuration cannot restore
a revoked administrator, a demoted organization owner, or a removed default-team
member. The default-team hint is returned only while the identity is still a
member; a CLI's explicit project or saved team selection takes precedence.

Administrator privilege does not grant the managed-domain root namespace.
Personal and member URLs use their normal namespaces. Applied team-owned public
URLs stay beneath the team's reserved readable or generated label.

## device lifecycle and sessions

`POST /v1/auth/device` returns a ten-minute attempt, a human code and approval URL,
and a separate 256-bit private polling credential. Control stores its digest and
encrypts the attempt's PKCE verifier, nonce, browser binding, verified identity,
and issued session. Browser sign-in uses a secure, HTTP-only, same-site cookie;
state is consumed once before the upstream code is redeemed. The person confirms
the terminal's code before control issues a session.

Polling is retryable after a lost response: the same private credential returns
the same issued session until the attempt expires. Cancellation and issuance
serialize on the attempt row; cancellation revokes an already-issued session.
The CLI preserves private cleanup state until cancellation succeeds. An uncertain
one-use provider exchange requires a fresh browser attempt. An uncertain local
session refresh requires explicit recovery; refresh credentials are never blindly
replayed. Local access/refresh sessions have absolute deadlines and explicit
revocation; provider refresh tokens are not retained.

## local development

The local Compose stack includes `internal/development/oidc`, a development-only standard
OIDC provider with one named `developer` identity. `task local:login` opens its
sign-in form and control's code confirmation, then saves the local control
session. The named developer is seeded once as a server administrator and owner
of the `local` organization team. Local development client secrets are fixed
fixture data. The provider binds only localhost through Compose.

The host's development TLS key stays mode 0600. A networkless preparation
container copies the certificate and key into an OIDC-only volume, sets the key
to mode 0600 and ownership to UID/GID 65532, then exits. The provider mounts that
volume read-only and runs as UID/GID 65532; it does not depend on Docker Desktop's
host-file permission translation.

An `oidc_admission_file` set in a `tnld` YAML/JSON configuration resolves relative
to that configuration's directory. Environment and command-line overrides keep
their normal working-directory-relative paths.

The normal local stack prerequisites and trust setup are described in
[contributing](../../../contributing.md). No keychain changes are needed for the
disposable PostgreSQL/OIDC integration test:

```console
mise exec -- task go:test:auth
mise exec -- task go:test:integration:auth
```

## team selection and company authentication

`tnl auth login --team studio` resolves the exact team name to its immutable ID
at control. Plain login uses the project or saved team when selected; otherwise
the browser offers team-name selection or personal sign-in. Selection does not
grant access. The CLI saves the resulting team ID with the new session only when
the identity has that membership.

Control creates a separate company intent for a company-required team, stores
its binding with the encrypted browser/device attempt, and uses its nonce with
the actual callback and PKCE challenge. Authorization parameters
`tnl_company_intent` and `tnl_company_binding` let the hosted broker resolve the
exact source through `POST /v1/auth/company-intents/{intent_id}/resolve`.
The broker must authenticate that source, then sign the canonical
`tnl_team_contexts` claim described in [company access](company-access.md).
The private CLI polling credential is never sent to the broker.

Both `/v1/auth/device/callback` and `/v1/browser/callback` preserve `TeamContexts`,
`Nonce`, `ClientID`, and `CompanyIntentBinding` into the session transaction.
`storeVerifiedCompanyContexts` consumes the intent and saves the selected team's
proof using the same generated `Queries`. There is no raw ID-token session
exchange endpoint or second context column.

For direct self-hosted providers, set `TNLD_OIDC_ADMISSION_FILE` to a bounded JSON
document. The provider emits ordinary signed OIDC claims, including `auth_time`
when control requests `max_age=0`; it does not need hosted custom claims:

```json
[
  {
    "team": "studio",
    "source_id": "company-entra",
    "subjects": ["exact-owner-subject"],
    "claim": { "name": "tid", "value": "exact-tenant-id" }
  }
]
```

Each rule applies only to the configured exact issuer. `subjects` are exact
subjects; an optional claim rule may match signed `tid`, `hd`, or a `groups`
entry. Subjects and the claim are alternative admission conditions. No email
merging or role claims are used. A rule seeds its team source once and supplies
eligibility inside the session transaction. First-time members are admitted as
members; removed memberships, demotions, manual suspensions, and bindings to
another source remain durable. Source replacement remains an explicit owner
operation. Removing a rule stops new mapped authentication; existing proof is
bounded by its original one-hour authentication deadline and current eligibility.

Reauthentication accepts an optional current `refresh_token` in the device start
request to bind the browser to the same identity. It copies only still-current
other-team proofs, preserving their original deadlines. Refresh never extends
source authentication time. A CLI replacing its session must call
`POST /v1/private-services/{private_service_id}/client-certificates` under the
new control session before using a cached client certificate. This existing API
rechecks current permission and rebinds the same device/CSR certificate to the
new session; a cache hit alone does not renew session provenance.
