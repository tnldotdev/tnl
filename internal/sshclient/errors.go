// package sshclient runs the system OpenSSH client over a managed TLS connection.
package sshclient

import (
	"errors"
	"fmt"
)

var (
	ErrSSHUnavailable = errors.New("OpenSSH was not found; install ssh and make it available on PATH")
	ErrInvalidSession = errors.New("invalid managed SSH session settings")
	ErrInvalidForward = errors.New("invalid SSH forwarding; use a loopback TCP listener and TCP destination")
	ErrInvalidHostKey = errors.New("invalid pinned SSH public host key")
)

// Error identifies an operation while retaining its underlying cause. its message
// deliberately excludes cause text, which may contain untrusted input.
type Error struct {
	Op  string
	Err error
}

func (e *Error) Error() string { return e.Op + " failed" }
func (e *Error) Unwrap() error { return e.Err }

// ExitError retains the exact OpenSSH exit status and the process error.
// signal exits use the shell convention, 128 plus the signal number.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return fmt.Sprintf("ssh exited with status %d", e.Code) }
func (e *ExitError) Unwrap() error { return e.Err }
func (e *ExitError) ExitCode() int { return e.Code }
