# Contributing

## Development

Install the pinned toolchain and run the repository checks through Task:

```console
mise trust
mise install
mise exec -- task format-check generate-check lint test build
```

Use `gofmt`, `goimports`, `go vet`, `staticcheck`, and `govulncheck` for Go.
Generated files are committed and must not drift from their source contracts.

The hosted TypeScript application is maintained separately from this public
server repository. Shared contracts and fixtures remain authoritative under
`api`.

## Engineering Rules

- Prefer the smallest design that completes the current phase.
- Reuse authoritative domain services, generated contracts, schema-derived
  types, and shared fixtures instead of creating parallel implementations.
- Use a maintained library instead of hand-rolling a capability. Ask before
  introducing a custom implementation when the tradeoff is unclear.
- Keep portable server packages independent of hosted protocol and domain types.
- Add tests for behavior, boundaries, and regressions. Do not add tautological
  tests solely to increase test counts.

## Dependencies And Notices

Every dependency must have a compatible license and a clear purpose. Direct
runtime dependencies that require attribution must add their notices to
`NOTICE`; generated release archives and native npm packages must include
`LICENSE`, `NOTICE`, and `THIRD_PARTY_LICENSES.txt`.
