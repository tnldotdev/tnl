# failure boundaries

Give an error a stable meaning where the operation knows what failed. Preserve
its cause for callers, then render safe text at the CLI, log, API, or browser
boundary.

## 1. choose the classification

Reuse an owned error type, sentinel, `failure.Reason`, or contract code when its
meaning fits. Use `errors.Is` and `errors.As` in Go and owned codes or types in
TypeScript. Classify provider errors by structured fields such as SQLSTATE or
HTTP status; never match their message text.

`internal/failure/reasons.go` owns each Go reason's class, message, action, and
retry policy. Add a reason when the operation needs a different meaning. Keep
IDs stable once machine output exposes them.

## 2. preserve the cause

Wrap the cause at the operation that can explain it:

```go
return failure.Wrap("finish invitation email", failure.ServerEmailLeaseStale,
    ErrEmailDeliveryLeaseStale)
```

The caller can still use `errors.Is(err, ErrEmailDeliveryLeaseStale)`. Internal
wrappers may add operation context with `%w`; TypeScript wrappers retain
`ErrorOptions.cause`. Cleanup failures should retain both the setup and cleanup
causes.

## 3. write safe messages and fields

Describe the failed condition directly: `email delivery lease is stale`.
Do not start with a package-name prefix such as `controlstate:`. Say what failed
and give a concrete next action when the reader can do something about it.

Output adapters use authored definitions, not raw `Error()` or provider
messages. Keep credentials, request bodies, database statements, and invalid
input values out of displayed text. Extra fields must be owned and approved,
such as a validated SQLSTATE, HTTP status, or retry duration.

Apply this rule to each form of output:

- **Configuration:** `failure.WrapSetting` accepts a declared setting name,
  without its value.
- **Stored failures:** worker fields and tunnel history keep the reason ID;
  resolve its definition when displaying it.
- **Measurements and protocol closes:** benchmark samples and close reasons use
  authored text and approved fields.

## 4. choose the retry policy

| Go policy          | when to use it                                                        |
| ------------------ | --------------------------------------------------------------------- |
| `NoRetry`          | the current operation cannot make progress, such as an obsolete claim |
| `RetryLater`       | the same operation can recover after a temporary failure              |
| `RetryAfterChange` | input, configuration, or state must change first                      |

Distinguish failures that can recover by retrying from those that need changed
input, configuration, or state. For example, unavailable OIDC signing keys are
a provider failure; a rejected signature is an authentication failure. Neither
should become an expired login merely because it happened during sign-in.

Keep cancellation and expected shutdown as control flow. Discard stale work
when its lease or assignment has been replaced. Bound transient retries and
retain the operation's idempotency key; do not automatically retry invalid
input, expired access, or malformed responses.

## 5. report at the boundary

| surface          | owner and output                                                                                |
| ---------------- | ----------------------------------------------------------------------------------------------- |
| `tnl`            | shared diagram renderer for human output; stable diagnostic codes and reasons in JSON or NDJSON |
| `tnld`           | `operatorlog.Report` with authored copy, approved fields, and request correlation               |
| HTTP APIs        | serving OpenAPI contract and its problem adapter                                                |
| tunnel protocol  | `pkg/protocol/tunnelv1` error codes and authored close reasons                                  |
| npm integrations | `TnlError` codes, definitions, and retry policy                                                 |
| feedback toolbar | `FeedbackError` codes and `safeFeedbackMessage` for views                                       |

Preserve HTTP status and HTML negotiation. Control, built-in authority, private
ingress, and private relay use the shared problem envelope: `type`, `title`,
`status`, `code`, `detail`, and `request_id`. Unexpected failures correlate the
request ID with operator logs; `detail` contains authored text. External usage
receivers own their HTTP contract.

Classify and report through the existing operation boundary. Keep helper
imports free of process-wide error-handler side effects.

## 6. verify the boundary

Use the lowest sufficient test layer to check:

- the specific classification and retry decision;
- preserved cause identity;
- safe output that excludes sensitive cause text;
- expected rejection, transient failure, cancellation, and malformed external
  data where the boundary handles them.

Keep command fixtures isolated from real client state. Edit generated contracts
through their authoritative source.
