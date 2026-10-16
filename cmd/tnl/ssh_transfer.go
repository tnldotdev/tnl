package main

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/sshclient"
)

type sshCopyCommand struct {
	sshRemoteFlags `embed:""`
	Source         string `arg:"" name:"source" help:"Local path or USER@HOST:path; exactly one endpoint must be remote."`
	Destination    string `arg:"" name:"destination" help:"Local path or USER@HOST:path."`
	Recursive      bool   `short:"r" help:"Copy directories recursively."`
}

type sshSFTPCommand struct {
	sshRemoteFlags `embed:""`
	Destination    string `arg:"" name:"user@host" help:"Existing nonroot account and managed SSH hostname."`
}

func isSSHChildCommand(args []string) bool {
	return len(args) == 2 && args[0] == "runtime" && args[1] == "ssh-child"
}

func sshCopyEndpoints(source, destination string) (string, sshclient.CopyOptions, error) {
	invalid := func() (string, sshclient.CopyOptions, error) {
		return "", sshclient.CopyOptions{}, &sshCommandError{message: "copy needs one local path and one managed SSH path", action: "use tnl ssh copy LOCAL USER@HOST:path or tnl ssh copy USER@HOST:path LOCAL", reason: failure.InvalidCommand, cause: sshclient.ErrInvalidTransfer}
	}
	type endpoint struct {
		remote, path string
	}
	parse := func(value string) (endpoint, bool) {
		if !sshclient.TransferPathValid(value) {
			return endpoint{}, false
		}
		prefix, path, colon := strings.Cut(value, ":")
		if colon && strings.Contains(prefix, "@") && !strings.ContainsAny(prefix, "/\\") {
			if _, _, err := parseSSHDestination(prefix); err != nil || !sshclient.TransferPathValid(path) {
				return endpoint{}, false
			}
			return endpoint{remote: prefix, path: path}, true
		}
		if strings.Contains(value, "://") {
			return endpoint{}, false
		}
		return endpoint{path: value}, true
	}
	from, fromOK := parse(source)
	to, toOK := parse(destination)
	if !fromOK || !toOK || (from.remote == "") == (to.remote == "") {
		return invalid()
	}
	if from.remote != "" {
		return from.remote, sshclient.CopyOptions{LocalPath: to.path, RemotePath: from.path}, nil
	}
	return to.remote, sshclient.CopyOptions{LocalPath: from.path, RemotePath: to.path, Upload: true}, nil
}

func withSSHTransferSession(ctx context.Context, flags sshRemoteFlags, destination, client string, visit func(sshclient.Session) error) error {
	account, hostname, err := parseSSHDestination(destination)
	if err != nil {
		return err
	}
	if err := sshclient.CheckTransferAvailable(client); err != nil {
		return err
	}
	session, err := openSSHVisitorSession(ctx, flags)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveVisitorPublicURL(ctx, session, hostname)
	if err != nil {
		return err
	}
	if err := selectSSHVisitorURL(item); err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	return visit(sshclient.Session{Executable: binary, ServerURL: session.authenticated.ServerEndpoint, StateDir: session.database.Root(), PublicURLID: item.Id, Hostname: item.CanonicalHostname, User: account, HostKey: *item.SshHostKey})
}

func runSSHCopy(ctx context.Context, flags sshCopyCommand, input io.Reader, output, diagnostics io.Writer) error {
	destination, options, err := sshCopyEndpoints(flags.Source, flags.Destination)
	if err != nil {
		return err
	}
	options.Recursive = flags.Recursive
	return withSSHTransferSession(ctx, flags.sshRemoteFlags, destination, "scp", func(session sshclient.Session) error {
		return sshclient.RunCopy(ctx, session, options, input, output, diagnostics)
	})
}

func runSSHSFTP(ctx context.Context, flags sshSFTPCommand, input io.Reader, output, diagnostics io.Writer) error {
	return withSSHTransferSession(ctx, flags.sshRemoteFlags, flags.Destination, "sftp", func(session sshclient.Session) error {
		return sshclient.RunSFTP(ctx, session, input, output, diagnostics)
	})
}
