# Papercuts

- macOS temporary screenshot paths expired before they could be inspected; attach screenshots directly when their contents are needed for debugging.
- Pinned repository tools such as `task` are not on the non-interactive shell PATH; invoke them through `mise exec --`.
- The oapi-codegen output path is relative to the working directory; invoke `go generate` instead of running it from the repository root.
- `task format-check` passes unstaged deleted Go paths to formatters during a rename; stage the rename or check the changed paths directly.
