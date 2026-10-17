package main

import (
	"errors"
	"io"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
)

// sshCommandError carries only authored diagnostic text. its cause remains
// available to callers but is never copied into a frame.
type sshCommandError struct {
	message string
	action  string
	reason  failure.Reason
	cause   error
}

func (e *sshCommandError) Error() string                 { return e.message }
func (e *sshCommandError) Unwrap() error                 { return e.cause }
func (e *sshCommandError) FailureReason() failure.Reason { return e.reason }

func validSSHAccount(user string) bool { return authorization.SSHUserValid(user) }

func writeSSHCommandError(output io.Writer, command string, err error) bool {
	var sshErr *sshCommandError
	if !errors.As(err, &sshErr) {
		return false
	}
	_ = clioutput.Write(output, clioutput.Frame{Command: command, State: "command failed", Blocks: []clioutput.Block{clioutput.Text(sshErr.message), clioutput.Text(sshErr.action)}})
	return true
}
