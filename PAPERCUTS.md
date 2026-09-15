`task go:test-integration` advertises the integration environment but fails immediately unless `TNL_TEST_POSTGRES_URL` is also supplied; the task or setup documentation should provide or explain the required PostgreSQL fixture.

`task generate-check` always compares generated directories to `HEAD`, so it cannot distinguish intentional uncommitted generated changes from generator drift in a dirty feature worktree.

While consolidating documentation, a patch failed because its paragraph context did not match the file's line wrapping. Retrying with complete existing paragraph boundaries avoided the mismatch.

`sqlc` reports `column "lease_expires_at" does not exist` when a relay renewal assigns that column from an expression involving the current row, although a plain argument assignment works. Returning an already-draining row from a second CTE avoids the generator limitation.

The default integration tier launched the isolated authoritative-DNS subprocess on macOS, where binding loopback TCP/UDP port 53 fails with `permission denied`. The test now skips on macOS; an unprivileged test-port design would allow local coverage.
