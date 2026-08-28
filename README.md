# tnl

a public url for localhost.

## Development

Install the pinned toolchain and run the repository checks:

```console
brew install mise
mise trust
mise install
mise exec -- task format-check lint test build
```

Go and TypeScript checks remain independent. Building the core Go commands does
not require Node.
