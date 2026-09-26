While reviewing Go code, `go` was not available on the default PATH; run Go commands with `mise exec --` and preserve `GOFLAGS=-tags=ts_omit_ssh` for direct commands.
After rebasing onto the latest main, the ingress session-close test intermittently saw a TCP reset instead of EOF; both are valid results of the test peer closing its connection.
When validating the runtime-load Compose file directly, a relative `RESULTS` value reported an undefined volume; use an absolute results path, as the Task target does.
During full race testing, the yamux peer-close fixture sometimes reported `io.ErrClosedPipe` instead of EOF because its send loop observed the closed `net.Pipe` first; accept either peer-close cause.
After a local 5,000-route run lost a relay, Docker had removed the container and no longer retained its kill event; the usual after-run status artifact was also missing. Capture the exit state and events before cleanup to distinguish OOM from other SIGKILL causes.
While checking Docker Desktop diagnostics, `docker desktop logs` rejected absolute `--since`/`--until` timestamps despite documenting systemd.time syntax; relative intervals such as `15m` worked.
