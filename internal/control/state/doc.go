// package state owns control's durable authorization and state transitions in
// PostgreSQL, not just database access. operations check current identities,
// grants, runs, leases, and revisions in the transaction that changes their state.
//
// authentication, teams, and domains establish ownership. public URLs, service
// runs, publisher connections, placement, and connector peers establish serving
// authority. previews, shares, and feedback retain their own access boundaries.
// certificate and DNS operations approve work that separate workers execute.
// operation-focused filenames group these families without splitting transactions.
//
// HTTP handlers and workers call this package; it never imports their owners.
// controlstatedb is generated from queries and migrations; edit those sources,
// not the generated methods, when changing database access or constraints.
// changes spanning operation families must retain one transaction and the existing
// lock order. file count alone is not a reason to split an authority boundary.
package state
