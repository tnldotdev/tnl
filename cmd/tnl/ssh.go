package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/sshclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type sshCommand struct {
	Run     sshRunCommand     `cmd:"" default:"withargs" help:"Visit a managed SSH host: tnl ssh USER@HOST [-L port:host:port] [-- command]."`
	Enable  sshEnableCommand  `cmd:"" help:"Enable managed SSH for existing nonroot accounts on this host."`
	Connect sshConnectCommand `cmd:"" hidden:""`
}

// SSH transport helpers use only a saved login, including when invoked by
// OpenSSH. an expired login must never prompt on the SSH protocol's stdin.
type sshRemoteFlags struct {
	ServerURL string `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the selected server."`
	StateDir  string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
}

type sshRunCommand struct {
	sshRemoteFlags `embed:""`
	Destination    string   `arg:"" name:"user@host" help:"Existing nonroot account and canonical hostname from tnl url available."`
	Command        []string `arg:"" optional:"" name:"command" help:"Remote command; use -- before its arguments."`
	Local          []string `name:"local" short:"L" sep:"none" help:"Loopback TCP forwarding: [bind:]port:host:port; repeat for each forward."`
	Dynamic        []string `name:"dynamic" short:"D" sep:"none" help:"Loopback SOCKS listener: [bind:]port; repeat for each listener."`
}

type sshConnectCommand struct {
	sshRemoteFlags `embed:""`
	PublicURLID    string `name:"public-url-id" required:""`
}

// sshCommandError carries only authored diagnostic text. its cause remains
// available to callers but is never copied into a frame or transport stdout.
type sshCommandError struct {
	message string
	action  string
	reason  failure.Reason
	cause   error
}

func (e *sshCommandError) Error() string                 { return e.message }
func (e *sshCommandError) Unwrap() error                 { return e.cause }
func (e *sshCommandError) FailureReason() failure.Reason { return e.reason }

func sshInputError() error {
	return &sshCommandError{message: "SSH needs an existing nonroot account and a public hostname", action: "run tnl ssh USER@HOST; find the hostname with tnl url available", reason: failure.InvalidCommand}
}

func parseSSHDestination(destination string) (string, string, error) {
	user, host, found := strings.Cut(destination, "@")
	canonical, err := naming.CanonicalizeHostname(host)
	if !found || !validSSHAccount(user) || err != nil || canonical != host || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return "", "", sshInputError()
	}
	return user, host, nil
}

func validSSHAccount(user string) bool {
	if user == "" || user == "root" || len(user) > 32 {
		return false
	}
	for i, c := range user {
		if c >= 'a' && c <= 'z' || c == '_' || i > 0 && (c >= '0' && c <= '9' || c == '-') {
			continue
		}
		return false
	}
	return true
}

func openSSHVisitorSession(ctx context.Context, flags sshRemoteFlags) (*teamSession, error) {
	server, database, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return nil, err
	}
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{ServerEndpoint: server, State: database})
	if err != nil {
		database.Close()
		return nil, err
	}
	return &teamSession{database: database, authenticated: authenticated}, nil
}

func selectSSHVisitorURL(item controlv1.AvailablePublicURL) error {
	host, err := naming.CanonicalizeHostname(item.CanonicalHostname)
	if !opaqueid.Valid(item.Id, opaqueid.PublicURLPrefix) || err != nil || host != item.CanonicalHostname || item.ServiceProtocol != "ssh" || item.PublicPort == nil || *item.PublicPort < 1024 || *item.PublicPort > 65535 || item.SshHostKey == nil || *item.SshHostKey == "" {
		return &sshCommandError{message: "the public URL is not a managed SSH host", action: "select a managed SSH hostname from tnl url available", reason: failure.ServerResponseInvalid}
	}
	return nil
}

func runSSH(ctx context.Context, flags sshRunCommand, input io.Reader, output, diagnostics io.Writer) error {
	user, hostname, err := parseSSHDestination(flags.Destination)
	if err != nil {
		return err
	}
	if err := sshclient.ValidateForwards(flags.Local, flags.Dynamic); err != nil {
		return err
	}
	if err := sshclient.CheckAvailable(); err != nil {
		return err
	}
	session, err := openSSHVisitorSession(ctx, flags.sshRemoteFlags)
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
		return failure.Wrap("locate tnl SSH helper", failure.ClientStateUnavailable, err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return err
	}
	return sshclient.Run(ctx, sshclient.Session{
		Executable: binary, ServerURL: session.authenticated.ServerEndpoint,
		StateDir: session.database.Root(), PublicURLID: item.Id,
		Hostname: item.CanonicalHostname, User: user, HostKey: *item.SshHostKey,
		LocalForwards: flags.Local, DynamicForwards: flags.Dynamic, Command: flags.Command,
	}, input, output, diagnostics)
}

func runSSHConnect(ctx context.Context, flags sshConnectCommand, input io.Reader, output io.Writer) error {
	if !opaqueid.Valid(flags.PublicURLID, opaqueid.PublicURLPrefix) {
		return sshInputError()
	}
	session, err := openSSHVisitorSession(ctx, flags.sshRemoteFlags)
	if err != nil {
		return err
	}
	defer session.Close()
	item, err := resolveVisitorPublicURL(ctx, session, flags.PublicURLID)
	if err != nil {
		return err
	}
	if err := selectSSHVisitorURL(item); err != nil {
		return err
	}
	certificate, _, err := createVisitorCertificate(ctx, session.authenticated.Control, item.Id)
	if err != nil {
		return err
	}
	address := net.JoinHostPort(item.CanonicalHostname, strconv.Itoa(int(*item.PublicPort)))
	return sshclient.Connect(ctx, address, item.CanonicalHostname, certificate, input, output)
}

func writeSSHCommandError(output io.Writer, command string, err error) bool {
	var sshErr *sshCommandError
	if !errors.As(err, &sshErr) {
		switch {
		case errors.Is(err, sshclient.ErrSSHUnavailable):
			sshErr = &sshCommandError{message: "OpenSSH is not installed or is not on PATH", action: "install the system OpenSSH client, then run tnl ssh again"}
		case errors.Is(err, sshclient.ErrInvalidForward):
			sshErr = &sshCommandError{message: "SSH forwarding needs a loopback TCP listener", action: "use -L port:host:port or -D port; Unix sockets and nonloopback listeners are not supported"}
		case errors.Is(err, sshclient.ErrInvalidHostKey):
			sshErr = &sshCommandError{message: "the managed SSH host key is invalid", action: "check the host's saved key with its administrator, then try again"}
		default:
			return false
		}
	}
	_ = clioutput.Write(output, clioutput.Frame{Command: command, State: "command failed", Blocks: []clioutput.Block{clioutput.Text(sshErr.message), clioutput.Text(sshErr.action)}})
	return true
}
