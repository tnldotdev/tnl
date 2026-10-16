package publisher

import (
	"context"
	"crypto/tls"
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

type AuthorizeSSHVisitor func(context.Context, Visitor, tls.ConnectionState, string) (controlclient.SSHVisitorDecision, error)

type SSHVisitorAuthorizer interface {
	AuthorizeSSHVisitor(context.Context, controlclient.VisitorCertificateScope, tls.ConnectionState, string) (controlclient.SSHVisitorDecision, error)
}

func sshVisitorAuthorization(client SSHVisitorAuthorizer, scope controlclient.VisitorCertificateScope) AuthorizeSSHVisitor {
	return func(ctx context.Context, visitor Visitor, state tls.ConnectionState, username string) (controlclient.SSHVisitorDecision, error) {
		if _, err := visitorAuthorizationKey(visitor, state); err != nil || client == nil || scope.PublicURLID != visitor.Run.PublicURLID || scope.PublishRunID != visitor.Run.PublishRunID || scope.PublishRunNumber != visitor.Run.Number || len(state.PeerCertificates) == 0 {
			return controlclient.SSHVisitorDecision{}, livevisitor.ErrDenied
		}
		bound := scope
		bound.SourceIP = visitor.Source.Addr().Unmap()
		decision, err := client.AuthorizeSSHVisitor(ctx, bound, state, username)
		if err != nil {
			var problem *controlclient.ProblemError
			if errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, controlclient.ErrNotFound) || errors.Is(err, controlclient.ErrStatusConflict) || errors.As(err, &problem) && (problem.Status == http.StatusForbidden || problem.Status == http.StatusUnauthorized || problem.Status == http.StatusNotFound || problem.Status == http.StatusConflict) {
				return controlclient.SSHVisitorDecision{}, errors.Join(livevisitor.ErrDenied, err)
			}
			return controlclient.SSHVisitorDecision{}, err
		}
		if decision.IdentityID == "" || decision.PublicURLID != scope.PublicURLID || decision.SSHUser != username || !time.Now().Before(decision.ValidUntil) || decision.ValidUntil.After(state.PeerCertificates[0].NotAfter) {
			return controlclient.SSHVisitorDecision{}, livevisitor.ErrDenied
		}
		return decision, nil
	}
}

func (d *tcpForwarding) serveSSH(ctx context.Context, visitor net.Conn, config *tls.Config, session *visitorSession) error {
	visitorTLS := config.Clone()
	visitorTLS.NextProtos = nil
	visitorTLS.ClientAuth = tls.RequireAnyClientCert
	visitorTLS.SessionTicketsDisabled = true
	secured := tls.Server(visitor, visitorTLS)
	if err := secured.HandshakeContext(ctx); err != nil {
		return err
	}
	state := secured.ConnectionState()
	decision, err := d.authorizeSSH(ctx, session.visitor, state, "")
	if err != nil {
		return err
	}
	runtime, err := managedssh.New(managedssh.Config{
		HostKey: d.ssh.HostKey, Users: d.ssh.Users, Runner: d.ssh.Runner,
		Authorize: func(ctx context.Context, identity managedssh.Identity, user string) (managedssh.Decision, error) {
			if identity.IdentityID != decision.IdentityID || identity.PublicURLID != decision.PublicURLID {
				return managedssh.Decision{}, livevisitor.ErrDenied
			}
			allowed, err := d.authorizeSSH(ctx, session.visitor, state, user)
			if err != nil {
				return managedssh.Decision{}, err
			}
			return managedssh.Decision{IdentityID: allowed.IdentityID, PublicURLID: allowed.PublicURLID, SSHUser: allowed.SSHUser, ValidUntil: allowed.ValidUntil}, nil
		},
	})
	if err != nil {
		return err
	}
	release, err := d.admit(ctx, session)
	if err != nil {
		return err
	}
	defer release()
	_ = visitor.SetDeadline(time.Time{})
	// only connection setup uses ctx's short deadline. the run owns the session.
	return runtime.ServeConn(session.life, secured, managedssh.Identity{IdentityID: decision.IdentityID, PublicURLID: decision.PublicURLID})
}
