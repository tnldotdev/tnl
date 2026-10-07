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

## email delivery

configure `TNLD_EMAIL_URL` with the mailer's HTTPS origin and `TNLD_EMAIL_TOKEN`
with a separate webhook credential. control sends `EmailDeliveryRequest`
from the authority OpenAPI schemas to `POST /api/internal/tnl/emails`:

```json
{
  "delivery_id": "ivt_0123456789abcdefghijkl",
  "type": "team_invitation",
  "to": "sam@example.com",
  "data": {
    "team_display_name": "studio",
    "secret": "<invitation-secret>",
    "expires_at": "2026-10-07T12:00:00Z"
  }
}
```

the mailer owns the template, sender, and SES call. HTTP 204 acknowledges sending
or an already-sent delivery ID; 400 and 422 reject a malformed job permanently.
other statuses and network failures retry with bounded exponential backoff.
the mailer records delivery IDs and must not log payloads or invitation secrets.
email transport is at-least-once: a crash after SES accepts but before saving the
receipt can send a duplicate, and the mailer cannot promise exactly-once delivery.

control commits one encrypted job with an email-restricted invitation, checks its
pending state before claiming it, and clears payloads after completion, expiry,
or revocation. revocation can race a send already in flight; acceptance still
checks current invitation state. storage-key rotation includes pending jobs.
without a mailer, invitations remain available through CLI-shared secrets.
