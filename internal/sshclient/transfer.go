package sshclient

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
)

type CopyOptions struct {
	LocalPath, RemotePath string
	Upload, Recursive     bool
}

// TransferPathValid bounds a filename without interpreting it as a shell command
// or a client option. remote paths are passed only to the sftp implementation.
func TransferPathValid(path string) bool {
	if path == "" || len(path) > 4096 {
		return false
	}
	for _, c := range path {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func CheckTransferAvailable(client string) error {
	if client != "scp" && client != "sftp" {
		return ErrInvalidTransfer
	}
	if err := CheckAvailable(); err != nil {
		return err
	}
	if _, err := exec.LookPath(client); err != nil {
		return &Error{Op: "find OpenSSH transfer client", Err: errors.Join(ErrTransferUnavailable, err)}
	}
	return nil
}

// RunCopy uses the system scp executable's sftp mode with one exact managed
// remote endpoint. absolute local paths cannot be mistaken for remote operands.
func RunCopy(ctx context.Context, session Session, options CopyOptions, stdin io.Reader, stdout, stderr io.Writer) error {
	if !TransferPathValid(options.LocalPath) || !TransferPathValid(options.RemotePath) || len(session.Command) != 0 || len(session.LocalForwards)+len(session.DynamicForwards) != 0 {
		return ErrInvalidTransfer
	}
	local, err := filepath.Abs(options.LocalPath)
	if err != nil {
		return &Error{Op: "resolve local copy path", Err: err}
	}
	return runClient(ctx, session, "scp", func(s Session, knownHosts, keyType, sshPath string) []string {
		args := append(connectionArgs(s, knownHosts, keyType), "-S", sshPath, "-s", "-B", "-o", "ClearAllForwardings=yes", "-o", "RequestTTY=no")
		if options.Recursive {
			args = append(args, "-r")
		}
		remote := s.User + "@" + s.Hostname + ":" + options.RemotePath
		if options.Upload {
			return append(args, "--", local, remote)
		}
		return append(args, "--", remote, local)
	}, stdin, stdout, stderr)
}

// RunSFTP opens the interactive system client with the same temporary pin and
// tls proxy as an ordinary session. its terminal streams remain caller-owned.
func RunSFTP(ctx context.Context, session Session, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(session.Command) != 0 || len(session.LocalForwards)+len(session.DynamicForwards) != 0 {
		return ErrInvalidTransfer
	}
	return runClient(ctx, session, "sftp", func(s Session, knownHosts, keyType, sshPath string) []string {
		args := append(connectionArgs(s, knownHosts, keyType), "-S", sshPath, "-o", "ClearAllForwardings=yes", "-o", "RequestTTY=no")
		return append(args, "--", s.User+"@"+s.Hostname)
	}, stdin, stdout, stderr)
}
