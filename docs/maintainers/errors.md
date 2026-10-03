# failure boundaries

Represent failures by reason and operation before rendering them for `tnl`,
`tnld`, or an HTTP client. `internal/failure` owns the reason definitions and
safe copy. Its wrapped cause remains available through `errors.Is` and
`errors.As`, but an output boundary must not build a message from `Error()`.

Add a new failure by declaring one namespaced reason and its explanation,
action, class, and retry policy in `internal/failure/reasons.go`. Wrap the
underlying error at the operation that knows what failed. If the failure needs
extra data, give its owner a typed field, such as a setting name or retry
duration; never pass credentials or arbitrary provider text as display fields.
Add an adapter only for surfaces where that reason can occur, and cover the
mapping with a test. The reason ID keeps its meaning once machine output uses
it; use a new ID for a different failure.

`tnl` presents safe text through the shared diagram renderer, and its NDJSON
events retain machine-readable reasons. `tnld` uses compact single-line
operational errors and logs, not diagrams. Public and private HTTP APIs own
their problem responses in the OpenAPI sources. The handwritten tunnel
protocol owns its error codes. These boundaries may share a reason without
sharing presentation or exposing an underlying cause.

Worker failure fields and local tunnel history store the reason ID, not the
untrusted provider, visitor, or database error text. Resolve a stored reason
through its definition when displaying it. Operator logs likewise use the
reason and operation; keep unexpected raw causes wrapped for internal error
identity without writing them to routine logs.
