// package clientauth separates ordinary authenticated requests from explicit
// login. Authenticate reuses an explicit access token or a saved control session
// and may refresh it; only Login and StartLogin initiate human approval.
//
// device login checkpoints live in server-scoped client state. private device
// challenges, nonces, assertions, and issued sessions use its secret protector.
// waiters share an operation lock; credential locks cover refresh, fencing, and
// installation, never browser approval. revisions reject cancelled work, and
// installation commits the session, selected server, and completion together.
//
// checkpoints precede one-time redemption and control exchange. after a lost
// response or process exit during those steps, the operation requires a new
// login instead of replaying a potentially consumed credential. an assertion or
// issued session already checkpointed can resume without another redemption.
package clientauth
