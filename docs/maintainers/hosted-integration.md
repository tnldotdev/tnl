# hosted integration

control owns tnl identities, teams, invitations, and publishing policy. the hosted
website supplies sign-in identity facts from its server-validated OIDC session.

configure `TNLD_WEB_SERVICE_SECRET` only on control and the website. the three
authority operations below accept that credential and bind every subject to
`TNLD_OIDC_ISSUER`; callers cannot supply an issuer, administrator flag, or role.
the credential cannot authenticate ordinary user or administrator operations.

| operation                              | input                                          | output                                                        |
| -------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------- |
| `POST /v1/service/identity-context`    | subject, display name, optional verified email | existing `IdentityContext`, including all current memberships |
| `POST /v1/service/invitations/preview` | identity facts and invitation secret           | team name, initial role, expiry                               |
| `POST /v1/service/invitations/accept`  | identity facts and invitation secret           | accepted membership                                           |

website resolution and CLI OIDC exchange provision the same `(issuer, subject)`
identity and personal team. website requests do not create control sessions.
the website must obtain subject and verified email from its own session, never
browser form fields. an absent verified email clears previously saved email facts.

the website remembers a selected team as a preference. before returning usage,
it reads current identity context and checks the selected team against those
memberships. control does not store the selected team or website billing state.

the OpenAPI source is `api/authority/v1/openapi.yaml`. keep hosted consumers on
the generated types from that source.
