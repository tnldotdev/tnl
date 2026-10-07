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
`failure.WrapSetting` accepts only known `TNLD_*` setting names, not their
values, and `tnld` names the failing setting in its one-line error.
Add an adapter only for surfaces where that reason can occur, and cover the
mapping with a test. The reason ID keeps its meaning once machine output uses
it; use a new ID for a different failure.

`tnl` presents safe text through the shared diagram renderer, and its NDJSON
events retain machine-readable reasons. `tnld` uses compact single-line
operational errors and logs, not diagrams. Public and private HTTP APIs own
their problem responses in the OpenAPI sources. The handwritten tunnel
protocol owns its error codes. These boundaries may share a reason without
sharing presentation or exposing an underlying cause.

Start error messages with the failed operation or condition, not the package
name. Write `email delivery lease is stale`, not
`controlstate: email delivery lease is stale`. The error type and reason identify
the owner; wrapping an operation preserves useful context and the original cause.

Control, built-in authority, private ingress, and private relay use one HTTP
problem envelope: `type`, `title`, `status`, `code`, `detail`, and `request_id`.
`code` is chosen from the serving API's OpenAPI source; `detail` is authored
safe text, and `request_id` correlates an unexpected failure with operator
logs. The public URL usage receiver is external and owns its own HTTP contract.

Worker failure fields and local tunnel history store the reason ID, not the
untrusted provider, visitor, or database error text. Resolve a stored reason
through its definition when displaying it. Operator logs likewise use the
reason and operation; keep unexpected raw causes wrapped for internal error
identity without writing them to routine logs.

Benchmark results and terminal failures use the same authored definitions. A
measurement may retain its HTTP status through an owned response error; it must
not store response bodies, arbitrary headers, or raw transport failures as
samples. QUIC close reasons likewise contain authored protocol text.

OIDC discovery and signing-key fetch failures mean the provider is unavailable;
a rejected signature or identity claim means authentication failed. The verifier
observes the original key-set error before the provider library formats it,
preserves network causes, bounds signing-key responses, and caches keys across
requests. Browser sign-in keeps these provider failures and storage failures
separate from expired login state.
