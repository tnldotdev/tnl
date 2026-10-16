package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os/user"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

type sshEnableCommand struct {
	scopedTeamFlags `embed:""`
	Name            string   `name:"name" required:"" help:"One lowercase hostname label beneath your selected domain or member namespace."`
	Users           []string `name:"user" required:"" sep:"none" help:"Existing nonroot local account to allow; repeat for each account."`
	Domain          string   `name:"domain" help:"Ready team domain; defaults to the team's default domain."`
}

// sshHostInstallPayload is the private stdin handoff to the root installer.
// enrollment grants only this saved URL; operator access/refresh tokens and the
// operator's client state directory must never be added to this payload.
type sshHostInstallPayload struct {
	Version        int      `json:"version"`
	Name           string   `json:"name"`
	Server         string   `json:"server"`
	PublicURLID    string   `json:"public_url_id"`
	Users          []string `json:"users"`
	EnrollmentKey  string   `json:"enrollment_key"`
	HostPrivateKey []byte   `json:"host_private_key"`
}

// the managed host runtime supplies these hooks. GrantSelf must create explicit
// identity grants, even for an owner. Install must pass the payload over private
// stdin to sudo and install a targetless root service job, without root login.
type sshEnableHooks struct {
	GrantSelf func(context.Context, *teamSession, string, string) error
	Install   func(context.Context, sshHostInstallPayload, io.Writer) error
}

func runSSHEnable(ctx context.Context, flags sshEnableCommand, output, diagnostics io.Writer) error {
	return runSSHEnableWithHooks(ctx, flags, output, diagnostics, sshEnableHooks{})
}

func runSSHEnableWithHooks(ctx context.Context, flags sshEnableCommand, output, diagnostics io.Writer, hooks sshEnableHooks) error {
	if err := validateSSHEnable(flags, user.Lookup); err != nil {
		return err
	}
	// fail before creating any server state until the managed installer and exact
	// self-grant API are wired. raw sshd publication is never a fallback.
	if hooks.GrantSelf == nil || hooks.Install == nil {
		return &sshCommandError{message: "managed SSH host installation is not wired in this build", action: "use a build with the managed host service installer", reason: failure.InvalidSetupInput}
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl ssh enable", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	hostname, domain, scope, err := resolvePublishHostname("", flags.Name, flags.Domain, current)
	if err != nil {
		return err
	}
	request := controlv1.CreatePublicURLRequest{CanonicalHostname: hostname, DomainId: domain.Id, PublicUrlScope: scope, Purpose: controlv1.App, TeamId: current.team.Id}
	if scope == controlv1.Member {
		request.MembershipId = &current.membership.Id
	}
	payload, err := prepareSSHHost(ctx, session.authenticated.Control, request, flags.Name, flags.Users, session.authenticated.ServerEndpoint, func(ctx context.Context, urlID, account string) error {
		return hooks.GrantSelf(ctx, session, urlID, account)
	})
	if err != nil {
		return err
	}
	if err := hooks.Install(ctx, payload, diagnostics); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl ssh enable", "installed", "", clioutput.Fields(
		clioutput.Field{Label: "hostname", Value: hostname},
		clioutput.Field{Label: "accounts", Value: strings.Join(payload.Users, ", ")},
		clioutput.Field{Label: "connect", Value: "tnl ssh " + payload.Users[0] + "@" + hostname},
	))
}

func validateSSHEnable(flags sshEnableCommand, lookup func(string) (*user.User, error)) error {
	canonical, err := naming.CanonicalizeHostname(flags.Name)
	if err != nil || canonical != flags.Name || strings.Contains(flags.Name, ".") || len(flags.Users) == 0 {
		return &sshCommandError{message: "SSH host setup needs a hostname label and nonroot accounts", action: "run tnl ssh enable --name workstation --user ACCOUNT", reason: failure.InvalidSetupInput, cause: err}
	}
	seen := map[string]bool{}
	for _, account := range flags.Users {
		if !validSSHAccount(account) || seen[account] {
			return &sshCommandError{message: "SSH accounts must be distinct existing nonroot account names", action: "repeat --user once for each existing nonroot account", reason: failure.InvalidSetupInput}
		}
		seen[account] = true
		entry, err := lookup(account)
		if err != nil || entry == nil || entry.Uid == "0" || entry.Username != account {
			return &sshCommandError{message: "an SSH account does not exist or belongs to root", action: "create a nonroot local account, then pass its name with --user", reason: failure.InvalidSetupInput, cause: err}
		}
	}
	return nil
}

type sshHostSetupAPI interface {
	CreatePublicURL(context.Context, controlv1.CreatePublicURLRequest, string) (controlv1.PublicURL, error)
	CreatePublisherEnrollment(context.Context, controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error)
}

func prepareSSHHost(ctx context.Context, api sshHostSetupAPI, request controlv1.CreatePublicURLRequest, name string, users []string, server string, grantSelf func(context.Context, string, string) error) (sshHostInstallPayload, error) {
	var empty sshHostInstallPayload
	canonicalServer, err := naming.CanonicalControlURL(server)
	if err != nil || canonicalServer != server || grantSelf == nil || len(users) == 0 {
		return empty, failure.Wrap("prepare SSH host", failure.InvalidSetupInput, errors.New("managed SSH installation requires an explicit server and account grants"))
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return empty, err
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return empty, err
	}
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	protocol, access := controlv1.Ssh, controlv1.Restricted
	request.Target, request.ServiceProtocol, request.AccessMode, request.SshHostKey = "", &protocol, &access, &pin
	key, err := randomIdempotencyKey()
	if err != nil {
		return empty, err
	}
	saved, err := api.CreatePublicURL(ctx, request, key)
	if err != nil {
		return empty, err
	}
	if !opaqueid.Valid(saved.Id, opaqueid.PublicURLPrefix) || saved.TeamId != request.TeamId || saved.CanonicalHostname != request.CanonicalHostname || saved.Target != "" || saved.ServiceProtocol != controlv1.Ssh || saved.AccessMode != controlv1.Restricted || saved.SshHostKey == nil || *saved.SshHostKey != pin || saved.Ephemeral {
		return empty, failure.Wrap("read SSH public URL", failure.ServerResponseInvalid, errors.New("control returned a different SSH host"))
	}
	for _, account := range users {
		if err := grantSelf(ctx, saved.Id, account); err != nil {
			return empty, err
		}
	}
	enrollment, err := api.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: saved.TeamId, PublicUrlId: &saved.Id, Name: name, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
	if err != nil {
		return empty, err
	}
	if !opaqueid.Valid(enrollment.Id, opaqueid.PublisherEnrollmentPrefix) || !strings.HasPrefix(enrollment.EnrollmentKey, enrollment.Id+".") || enrollment.TeamId != saved.TeamId || enrollment.Kind != "saved_url" || enrollment.PublicUrlId == nil || *enrollment.PublicUrlId != saved.Id || enrollment.DomainId != nil || enrollment.Namespace != nil || !enrollment.ExpiresAt.After(time.Now()) {
		return empty, failure.Wrap("read SSH publisher enrollment", failure.ServerResponseInvalid, errors.New("control returned a different enrollment scope"))
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return empty, err
	}
	return sshHostInstallPayload{Version: 1, Name: name, Server: server, PublicURLID: saved.Id, Users: slices.Clone(users), EnrollmentKey: enrollment.EnrollmentKey, HostPrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}, nil
}
