# website team usage authorization

The website may read a team's usage only after a successful
`GET /v1/service/teams/{team_id}/usage-authorization` for that request. Any active
member role is eligible, including the personal-team owner. Identity-context
memberships are selection metadata; inactive memberships remain in that list.

The endpoint requires the website credential and a configured-issuer human
assertion. Its nonce uses `tnl.team-usage.actor.v1`, the exact HTTP method,
escaped path and raw query, and the SHA-256 digest of the empty body. The
website reads the current browser session without its cookie cache and signs
a new assertion for every read, with the original `auth_time`, a unique `jti`,
and a lifetime bounded by both the session and 60 seconds.

Control consumes the assertion and its issuer/JTI in the authorization
transaction. It rechecks the enabled identity and active membership, then the
current company connection, source, revision, subject, eligibility deadline,
and source authentication time when required. Company proof must use the
assertion's authentication time. Removed, suspended, directory-ineligible, and
expired memberships do not authorize a read.

The 204 response is uncached, point-in-time permission for one usage read. It
returns no inventory, visitor credential, or management authority. The website
usage query is a later operation in a separate database; authorization and the
query are not one cross-database transaction. Service management APIs retain
their owner/admin checks.
