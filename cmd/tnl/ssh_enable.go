package main

import (
	"context"
	"errors"
	"io"
	"os/user"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/managedssh"
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
	Version             int       `json:"version"`
	Name                string    `json:"name"`
	Server              string    `json:"server"`
	PublicURLID         string    `json:"public_url_id"`
	TeamID              string    `json:"team_id"`
	Hostname            string    `json:"hostname"`
	Users               []string  `json:"users"`
	EnrollmentKey       string    `json:"enrollment_key"`
	EnrollmentExpiresAt time.Time `json:"enrollment_expires_at,omitempty"`
	HostPrivateKey      []byte    `json:"host_private_key"`
}

func (sshHostInstallPayload) String() string     { return "private SSH host install payload" }
func (p sshHostInstallPayload) GoString() string { return p.String() }

// the concrete adapters are replaceable in tests so setup never invokes sudo or
// a host service manager there.
type sshEnableHooks struct {
	Prepare   func(context.Context, io.Writer) error
	GrantSelf func(context.Context, *teamSession, string, string, ...string) error
	Install   func(context.Context, sshHostInstallPayload, io.Writer) error
}

func runSSHEnable(ctx context.Context, flags sshEnableCommand, output, diagnostics io.Writer) error {
	return runSSHEnableWithHooks(ctx, flags, output, diagnostics, sshEnableHooks{
		Prepare: prepareSSHHostInstall, GrantSelf: grantSSHHostSelfAccess, Install: installSSHHost,
	})
}

func runSSHEnableWithHooks(ctx context.Context, flags sshEnableCommand, output, diagnostics io.Writer, hooks sshEnableHooks) error {
	if err := validateSSHEnable(flags, user.Lookup); err != nil {
		return err
	}
	if hooks.GrantSelf == nil || hooks.Install == nil {
		return failure.Wrap("prepare SSH installer", failure.InvalidSetupInput, errors.New("SSH installer adapters are required"))
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
	state, err := session.store.LockSSHHostSetup(ctx, current.team.Id, hostname)
	if err != nil {
		return err
	}
	defer state.Close()
	journal, err := openSSHHostSetup(ctx, state, request, flags.Name, flags.Users, session.authenticated.ServerEndpoint, session.identity.Identity.Id)
	if err != nil {
		return err
	}
	if hooks.Prepare != nil {
		if err := hooks.Prepare(ctx, diagnostics); err != nil {
			return err
		}
	}
	payload, err := completeSSHHostSetup(ctx, session.authenticated.Control, journal, hooks.Install, diagnostics, func(ctx context.Context, urlID, account string) error {
		return hooks.GrantSelf(ctx, session, urlID, account, journal.record.GrantKeys[account])
	})
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl ssh enable", "installed", "", clioutput.Fields(
		clioutput.Field{Label: "hostname", Value: hostname},
		clioutput.Field{Label: "accounts", Value: strings.Join(payload.Users, ", ")},
		clioutput.Field{Label: "connect", Value: "tnl ssh " + payload.Users[0] + "@" + hostname},
		clioutput.Field{Label: "status", Value: "sudo tnl service status " + payload.Name},
		clioutput.Field{Label: "stop", Value: "sudo tnl service stop " + payload.Name},
	))
}

func validateSSHEnable(flags sshEnableCommand, lookup func(string) (*user.User, error)) error {
	canonical, err := naming.CanonicalizeHostname(flags.Name)
	if err != nil || canonical != flags.Name || !naming.ValidServiceName(flags.Name) || strings.Contains(flags.Name, ".") || len(flags.Users) == 0 {
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

func prepareSSHHost(ctx context.Context, api sshHostSetupAPI, request controlv1.CreatePublicURLRequest, name string, users []string, server string, grantSelf func(context.Context, string, string) error, resume ...*sshHostSetupJournal) (sshHostInstallPayload, error) {
	var empty sshHostInstallPayload
	canonicalServer, err := naming.CanonicalControlURL(server)
	if err != nil || canonicalServer != server || grantSelf == nil || len(users) == 0 {
		return empty, failure.Wrap("prepare SSH host", failure.InvalidSetupInput, errors.New("managed SSH installation requires an explicit server and account grants"))
	}
	var journal *sshHostSetupJournal
	if len(resume) != 0 {
		journal = resume[0]
	} else {
		record, err := newSSHHostSetup(request, name, users, server, "")
		if err != nil {
			return empty, err
		}
		journal = &sshHostSetupJournal{record: record}
	}
	record := journal.record
	signer, err := managedssh.ParseHostKey(record.HostPrivateKey)
	if err != nil {
		return empty, invalidSSHSetupState()
	}
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	protocol, access := controlv1.Ssh, controlv1.Restricted
	request.Target, request.ServiceProtocol, request.AccessMode, request.SshHostKey = "", &protocol, &access, &pin
	if record.PublicURLID == "" {
		saved, err := api.CreatePublicURL(ctx, request, record.URLKey)
		if err != nil {
			if errors.Is(err, controlclient.ErrNameUnavailable) {
				return empty, &sshCommandError{message: "the hostname belongs to another saved public URL setup", action: "select another --name or inspect the original host; enable cannot replace its key", reason: failure.ServerConflict, cause: err}
			}
			return empty, err
		}
		if !opaqueid.Valid(saved.Id, opaqueid.PublicURLPrefix) || saved.TeamId != request.TeamId || saved.CanonicalHostname != request.CanonicalHostname || saved.Target != "" || saved.ServiceProtocol != controlv1.Ssh || saved.AccessMode != controlv1.Restricted || saved.SshHostKey == nil || *saved.SshHostKey != pin || saved.Ephemeral {
			return empty, failure.Wrap("read SSH public URL", failure.ServerResponseInvalid, errors.New("control returned a different SSH host"))
		}
		record.PublicURLID = saved.Id
		if err := journal.save(ctx); err != nil {
			return empty, err
		}
	}
	for _, account := range record.Users {
		if record.Granted[account] {
			continue
		}
		if err := grantSelf(ctx, record.PublicURLID, account); err != nil {
			return empty, err
		}
		record.Granted[account] = true
		if err := journal.save(ctx); err != nil {
			return empty, err
		}
	}
	if record.EnrollmentKey == "" || !record.InstallAttempted && !record.EnrollmentExpiresAt.After(time.Now()) {
		if err := issueSSHHostEnrollment(ctx, api, journal); err != nil {
			return empty, err
		}
	}
	return sshHostSetupPayload(record), nil
}

func grantSSHHostSelfAccess(ctx context.Context, session *teamSession, urlID, account string, idempotency ...string) error {
	identity := session.identity.Identity.Id
	if !opaqueid.Valid(identity, opaqueid.IdentityPrefix) || !validSSHAccount(account) {
		return failure.Wrap("select SSH self grant", failure.ServerResponseInvalid, errors.New("authenticated identity or SSH account is invalid"))
	}
	var key string
	if len(idempotency) != 0 {
		key = idempotency[0]
	} else {
		var err error
		key, err = randomIdempotencyKey()
		if err != nil {
			return err
		}
	}
	if !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) {
		return invalidSSHSetupState()
	}
	grant, err := session.authenticated.Control.CreateIdentityVisitorGrant(ctx, urlID, key, controlv1.CreateIdentityVisitorGrantRequest{IdentityId: identity, SshUser: &account})
	if err != nil {
		return err
	}
	if grant.PublicUrlId != urlID || grant.Kind != "identity" || grant.IdentityId == nil || *grant.IdentityId != identity || grant.SshUser == nil || *grant.SshUser != account || grant.RevokedAt != nil {
		return failure.Wrap("read SSH self grant", failure.ServerResponseInvalid, errors.New("control returned a different identity grant"))
	}
	return nil
}
