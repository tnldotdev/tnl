# managed ssh child boundary

Managed ssh starts the same installed executable with `runtime ssh-child` for
each session or forwarded connection. The serving process must have real and
effective uid 0. It never changes its own user or groups. Each child resolves
the exact configured account name again and rejects every uid-0 account,
including aliases. Numeric user IDs are not accepted.

The child changes supplementary groups, then gid, then uid through Go's
all-thread `syscall` setters. Failures stop setup before any requested work.
Linux and macOS are supported; other platforms fail closed. Tests can inject
an unexported same-uid runner and a test-only subprocess entry point. Neither
the production entry point nor its setup message can enable that exception.

This is a direct credential change, compatible with a root systemd service's
`NoNewPrivileges=true`. It does not use `su`, `login`, PAM, account creation,
or service changes. It does not open a login session or apply PAM account,
session, resource-limit, or environment modules. The shell comes from the
local account record (macOS also checks Directory Services), defaulting to
`/bin/sh`. The child's privileges are those of the selected existing account;
this is not a filesystem or network sandbox.

## setup and descriptors

Arguments identify only the hidden entry point. A bounded, validated JSON
message on inherited fd 3 carries the account, operation, command, terminal,
and optional forwarding address. Fd 4 reports readiness or a generic setup
failure separately from the command's exit code. Fd 5 carries terminal sizes.
No setup field selects an environment, executable, credential, or privilege
exception. Unknown fields, extra JSON values, invalid sizes, and oversized
messages are rejected. Raw setup and target errors are not sent to the SSH
client.

Before user work, the child closes unrelated inheritable descriptors. Go
runtime descriptors already marked close-on-exec remain live; setup and
control descriptors are explicitly close-on-exec. The shell receives only
standard input, output, and error. SFTP runs in the dropped child using
`sftp.NewServer` on standard input/output. Forwarding connects from the
dropped child; the privileged server only owns a local socketpair endpoint.

The child changes to the account's home and clears the inherited environment.
Shells get fixed `PATH=/usr/local/bin:/usr/bin:/bin`, `HOME`, `USER`, `LOGNAME`,
`SHELL`, and the validated requested `TERM`, when present. Shell startup files
remain under the account owner's control. Commands are passed as one raw
argument to that account's shell with `-c`, after the credential change.

## lifecycle

A terminal request starts the shell on a PTY and applies initial and subsequent
window sizes. Input EOF sends the terminal EOF character; output is drained
after shell exit. Nonterminal sessions preserve standard-input EOF directly.
Cancellation signals the child's process group; the child kills its shell
process group and the terminal's foreground process group, then waits for the
shell. The parent waits for the child before returning.
The normal shell exit code is a session result, not a setup failure.

Forwarding reports a successful target connection before returning a
`net.Conn`. The socketpair preserves EOF and `CloseWrite`; request EOF
half-closes the target while allowing its response to drain. Target output EOF
also preserves the input direction until the visitor finishes writing. Closing the
connection or cancelling its context terminates and joins the child.
As with ordinary Unix process-group cleanup, an account's program can
deliberately detach into another session; this runtime is not a process
containment mechanism.
