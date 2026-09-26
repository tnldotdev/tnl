While reviewing Go code, `go` was not available on the default PATH; run Go commands with `mise exec --` and preserve `GOFLAGS=-tags=ts_omit_ssh` for direct commands.
After rebasing onto the latest main, the ingress session-close test intermittently saw a TCP reset instead of EOF; both are valid results of the test peer closing its connection.
When validating the runtime-load Compose file directly, a relative `RESULTS` value reported an undefined volume; use an absolute results path, as the Task target does.
During full race testing, the yamux peer-close fixture sometimes reported `io.ErrClosedPipe` instead of EOF because its send loop observed the closed `net.Pipe` first; accept either peer-close cause.
