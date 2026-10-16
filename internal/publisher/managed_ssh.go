package publisher

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/livevisitor"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"golang.org/x/crypto/ssh"
)

// SSHConfig is host-owned configuration; no private target or remote command
// can select these users or change the installed host key.
type SSHConfig struct {
	HostKey ssh.Signer
	Users   []string
	Runner  *managedssh.Runner
}

func (c *SSHConfig) publicKey() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c.HostKey.PublicKey())))
}

func validateManagedSSH(c *SSHConfig, target string, targetTLS bool, tlsName string, options localproxy.TargetOptions) error {
	if c == nil || c.HostKey == nil || c.HostKey.PublicKey().Type() != ssh.KeyAlgoED25519 || managedssh.ValidateUserNames(c.Users) != nil || target != "" || targetTLS || tlsName != "" || options.ServerName != "" || options.RootCAs != nil {
		return managedssh.ErrConfiguration
	}
	return nil
}

// PublisherSSHAttempt is implemented by a client scoped to one publish run
// token. the generated API adapter belongs with the control API integration;
// a missing adapter fails publication closed.
type PublisherSSHAttempt = managedssh.PublisherSSHAttempt

func (d *tcpForwarding) serveSSH(conn net.Conn, session *visitorSession) error {
	v := session.visitor
	if !v.Header.AccessPending || v.Run.Hostname == "" || v.Run.PublicURLID == "" || v.Run.PublishRunID == "" || v.Run.Number == 0 ||
		v.Header.PublicURLID != v.Run.PublicURLID || v.Header.PublishRunID != v.Run.PublishRunID || v.Header.PublishRunNumber != v.Run.Number ||
		v.Header.VisitorConnectionID == "" || !v.Source.IsValid() || v.Source.Addr().Zone() != "" || d.attempts == nil || session.promote == nil {
		return livevisitor.ErrDenied
	}
	bound := managedssh.Binding{Hostname: v.Run.Hostname, PublicURLID: v.Run.PublicURLID, PublishRunID: v.Run.PublishRunID, PublishRunNumber: v.Run.Number,
		VisitorConnectionID: v.Header.VisitorConnectionID, Source: v.Source}
	var release func()
	runtime, err := managedssh.New(managedssh.Config{
		HostKey: d.ssh.HostKey, Users: d.ssh.Users, Runner: d.ssh.Runner, Binding: bound, Attempts: d.attempts, ControlURL: d.controlURL,
		Authorize: sshSessionAuthorization(d.attempts, bound),
		Promote: func(ctx context.Context) error {
			var err error
			release, err = d.admit(ctx, session)
			return err
		},
	})
	if err != nil {
		return err
	}
	defer func() {
		if release != nil {
			release()
		}
	}()
	return runtime.ServeConn(session.life, conn)
}

func sshSessionAuthorization(client PublisherSSHAttempt, bound managedssh.Binding) func(context.Context, managedssh.Identity, string) (managedssh.Decision, error) {
	return func(ctx context.Context, identity managedssh.Identity, user string) (managedssh.Decision, error) {
		check := bound
		check.Username = user
		check.SessionID = identity.SessionID
		current, err := client.RecheckSSHSession(ctx, check, identity.IdentityID)
		if err != nil {
			var problem *controlclient.ProblemError
			if errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, controlclient.ErrNotFound) || errors.Is(err, controlclient.ErrStatusConflict) || errors.As(err, &problem) && (problem.Status == http.StatusUnauthorized || problem.Status == http.StatusForbidden || problem.Status == http.StatusNotFound || problem.Status == http.StatusConflict) {
				return managedssh.Decision{}, errors.Join(livevisitor.ErrDenied, err)
			}
			return managedssh.Decision{}, err
		}
		if !current.Approved || current.IdentityID != identity.IdentityID || current.Binding != check || !time.Now().Before(current.ValidUntil) {
			return managedssh.Decision{}, livevisitor.ErrDenied
		}
		return managedssh.Decision{IdentityID: identity.IdentityID, PublicURLID: bound.PublicURLID, SSHUser: user, ValidUntil: current.ValidUntil}, nil
	}
}
