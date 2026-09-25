While reviewing Go code, `go` was not available on the default PATH; run Go commands with `mise exec --` and preserve `GOFLAGS=-tags=ts_omit_ssh` for direct commands.
After rebasing onto the latest main, the ingress session-close test intermittently saw a TCP reset instead of EOF; both are valid results of the test peer closing its connection.
