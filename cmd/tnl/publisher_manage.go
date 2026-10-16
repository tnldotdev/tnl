package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherCommand struct {
	Current   publisherCurrentCommand   `cmd:"" help:"Show the selected local or file-backed publisher without exposing its key."`
	Setup     publisherSetupCommand     `cmd:"" help:"Set up a local publisher for your HTTP namespace."`
	Provision publisherProvisionCommand `cmd:"" help:"Write a portable scoped publisher file for deployment."`
	Enroll    publisherEnrollCommand    `cmd:"" help:"Issue one-use enrollment for a saved URL or HTTP namespace."`
	List      publisherListCommand      `cmd:"" help:"List publisher identities and grants."`
	Revoke    publisherRevokeCommand    `cmd:"" help:"Revoke a publisher identity."`
	Grant     struct {
		Add    publisherGrantAddCommand    `cmd:"" help:"Add a saved URL or HTTP namespace grant."`
		Revoke publisherGrantRevokeCommand `cmd:"" help:"Revoke one publisher grant."`
	} `cmd:"" help:"Manage publisher grants."`
}
type publisherSetupCommand struct {
	scopedTeamFlags `embed:""`
	Namespace       bool   `help:"Set up this team's HTTP namespace for tnl.open."`
	URL             string `name:"url" help:"Set up one saved development public URL by ID."`
	Domain          string `help:"Ready team domain; defaults to the team's default domain."`
}
type publisherProvisionCommand struct {
	scopedTeamFlags `embed:""`
	Namespace       bool   `help:"Grant temporary HTTP URLs in your namespace."`
	URL             string `name:"url" help:"Saved public URL ID for an exact grant."`
	Domain          string `help:"Ready team domain for a namespace grant."`
	OutputFile      string `name:"output-file" type:"path" required:"" help:"New private file for deployment; never overwrites an existing file."`
}

func runPublisherSetup(ctx context.Context, f publisherSetupCommand, output, diagnostics io.Writer) error {
	if f.Namespace == (f.URL != "") || !f.Namespace && f.Domain != "" {
		return publisherCLIError("select --namespace or --url <public-url-id> for local setup")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher setup", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if f.URL != "" {
		if !opaqueid.Valid(f.URL, opaqueid.PublicURLPrefix) {
			return publisherCLIError("pass a saved public URL ID with --url")
		}
		current, err := session.current(ctx)
		if err != nil {
			return err
		}
		route, err := session.authenticated.Control.GetPublicURL(ctx, f.URL)
		if err != nil {
			return err
		}
		if route.TeamId != current.team.Id || route.Purpose != controlv1.App || route.Ephemeral || route.LifecycleState != controlv1.Enabled {
			return nativeauth.ErrScope
		}
		n, identity, err := nativeauth.EnsureOwner(ctx, session.store, session.authenticated.Control, session.authenticated.Authority, route)
		if err != nil {
			return err
		}
		if _, err := n.Access(ctx); err != nil {
			return err
		}
		return writeHumanFrame(output, "tnl publisher setup", "ready", "saved public URL publisher is set up", clioutput.Fields(
			clioutput.Field{Label: "public URL", Value: route.CanonicalHostname}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId},
		))
	}
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	domain, err := readyDomain(current, f.Domain)
	if err != nil {
		return err
	}
	namespace, valid := current.namespace(domain)
	if !valid || namespace == "" {
		return publisherCLIError("selected domain has no HTTP namespace")
	}
	_, identity, err := nativeauth.EnsureNamespace(ctx, session.store, session.authenticated.Control, session.authenticated.Authority, current.team.Id, domain.Id, namespace)
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher setup", "ready", "tnl.open can now publish in this namespace", clioutput.Fields(
		clioutput.Field{Label: "namespace", Value: namespace}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId},
	))
}

func runPublisherProvision(ctx context.Context, f publisherProvisionCommand, output, diagnostics io.Writer) error {
	if f.OutputFile == "" {
		return publisherCLIError("pass --output-file for the portable publisher identity")
	}
	if _, err := os.Lstat(f.OutputFile); err == nil {
		return credentialfile.ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return credentialfile.ErrInvalid
	}
	if f.Namespace == (f.URL != "") || !f.Namespace && f.Domain != "" {
		return publisherCLIError("select --namespace or --url <public-url-id>")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher provision", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	url, domain, err := publisherCLIScope(current, f.URL, f.Namespace, f.Domain)
	if err != nil {
		return err
	}
	var namespace string
	if domain != nil {
		d, err := readyDomain(current, f.Domain)
		if err != nil {
			return err
		}
		var valid bool
		namespace, valid = current.namespace(d)
		if !valid || namespace == "" {
			return publisherCLIError("selected domain has no HTTP namespace")
		}
	}
	e, err := session.authenticated.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: current.team.Id, PublicUrlId: url, DomainId: domain, Name: "deployment", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
	if err != nil {
		return err
	}
	if !opaqueid.Valid(e.Id, opaqueid.PublisherEnrollmentPrefix) || !strings.HasPrefix(e.EnrollmentKey, e.Id+".") || e.TeamId != current.team.Id || !e.ExpiresAt.After(time.Now()) || url != nil && (e.Kind != "saved_url" || e.PublicUrlId == nil || *e.PublicUrlId != *url || e.DomainId != nil || e.Namespace != nil) || domain != nil && (e.Kind != "namespace" || e.PublicUrlId != nil || e.DomainId == nil || *e.DomainId != *domain || e.Namespace == nil || *e.Namespace != namespace) {
		return failure.Wrap("read publisher enrollment", failure.ServerResponseInvalid, errors.New("control returned a different publisher scope"))
	}
	n, identity, err := nativeauth.EnrollNative(ctx, session.store, session.authenticated.Control, session.authenticated.Authority, e.EnrollmentKey)
	if err != nil {
		return err
	}
	if identity.TeamId != current.team.Id || url != nil && (identity.Kind != "saved_url" || identity.PublicUrlId == nil || *identity.PublicUrlId != *url || identity.DomainId != nil || identity.Namespace != nil) || domain != nil && (identity.Kind != "namespace" || identity.PublicUrlId != nil || identity.DomainId == nil || *identity.DomainId != *domain || identity.Namespace == nil || *identity.Namespace != namespace) {
		return nativeauth.ErrScope
	}
	if _, err := n.Access(ctx); err != nil {
		return err
	}
	saved, found, err := session.store.PublisherSigningIdentity(ctx, "publisher:"+identity.ClientId)
	if err != nil {
		return err
	}
	if !found {
		return nativeauth.ErrScope
	}
	fCred, err := credentialfile.New(session.authenticated.ServerEndpoint, identity, saved.PrivateValue)
	if err != nil {
		return err
	}
	if err := credentialfile.Write(f.OutputFile, fCred); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher provision", "created", "mount the file and set TNL_PUBLISHER_FILE", clioutput.Fields(
		clioutput.Field{Label: "file", Value: f.OutputFile}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId},
	))
}

type publisherEnrollCommand struct {
	scopedTeamFlags `embed:""`
	PublicURLID     string `arg:"" optional:"" name:"public-url-id" help:"Enabled saved public URL ID."`
	Name            string `default:"publisher" help:"Lowercase publisher name."`
	Namespace       bool   `help:"Grant temporary HTTP URLs in your authorized namespace."`
	Domain          string `help:"Ready team domain for namespace enrollment."`
	Automation      bool   `help:"Expire the initial grant after one hour."`
}
type publisherListCommand struct {
	scopedTeamFlags `embed:""`
	After           string `help:"Continue after this publisher identity ID."`
}
type publisherRevokeCommand struct {
	scopedTeamFlags `embed:""`
	ID              string `arg:"" name:"publisher-id"`
}
type publisherGrantAddCommand struct {
	scopedTeamFlags `embed:""`
	PublisherID     string `arg:"" name:"publisher-id"`
	PublicURLID     string `name:"public-url-id" help:"Saved URL to grant."`
	Namespace       bool   `help:"Grant temporary HTTP URLs in your namespace."`
	Domain          string `help:"Ready team domain for a namespace grant."`
}
type publisherGrantRevokeCommand struct {
	scopedTeamFlags `embed:""`
	PublisherID     string `arg:"" name:"publisher-id"`
	GrantID         string `arg:"" name:"grant-id"`
}

func publisherCLIError(message string) error {
	return failure.Wrap("select publisher identity", failure.InvalidTunnelFlags, errors.New(message))
}

func publisherCLIScope(current teamContext, urlID string, namespace bool, domain string) (*string, *string, error) {
	if namespace == (urlID != "") || !namespace && domain != "" {
		return nil, nil, publisherCLIError("select a saved public URL ID or --namespace")
	}
	if !namespace {
		if !opaqueid.Valid(urlID, opaqueid.PublicURLPrefix) {
			return nil, nil, publisherCLIError("pass a saved public URL ID")
		}
		return &urlID, nil, nil
	}
	d, err := readyDomain(current, domain)
	if err != nil {
		return nil, nil, err
	}
	return nil, &d.Id, nil
}

func runPublisherEnroll(ctx context.Context, f publisherEnrollCommand, output, diagnostics io.Writer) error {
	if !naming.ValidServiceName(f.Name) {
		return publisherCLIError("pass a lowercase publisher name")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher enroll", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	url, domain, err := publisherCLIScope(current, f.PublicURLID, f.Namespace, f.Domain)
	if err != nil {
		return err
	}
	kind := controlv1.CreatePublisherEnrollmentRequestKindInstalled
	if f.Automation {
		kind = controlv1.CreatePublisherEnrollmentRequestKindAutomation
	}
	e, err := session.authenticated.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: current.team.Id, PublicUrlId: url, DomainId: domain, Name: f.Name, Kind: kind})
	if err != nil {
		return err
	}
	if !opaqueid.Valid(e.Id, opaqueid.PublisherEnrollmentPrefix) || e.EnrollmentKey == "" || !e.ExpiresAt.After(time.Now()) || e.TeamId != current.team.Id || url != nil && (e.PublicUrlId == nil || *e.PublicUrlId != *url) {
		return failure.Wrap("read publisher enrollment", failure.ServerResponseInvalid, errors.New("control returned a different enrollment"))
	}
	// one-use enrollment secrets remain exact raw values on stdout.
	_, err = fmt.Fprintln(output, e.EnrollmentKey)
	return err
}

func runPublisherList(ctx context.Context, f publisherListCommand, output, diagnostics io.Writer) error {
	if f.After != "" && !opaqueid.Valid(f.After, opaqueid.PublisherIdentityPrefix) {
		return publisherCLIError("--after requires a publisher identity ID")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	page, err := session.authenticated.Control.ListPublisherIdentities(ctx, current.team.Id, f.After)
	if err != nil {
		return err
	}
	blocks := []clioutput.Block{}
	for _, p := range page.Identities {
		state := "active"
		if p.RevokedAt != nil {
			state = "revoked"
		}
		fields := []clioutput.Field{{Label: "publisher", Value: p.Id}, {Label: "kind", Value: string(p.Kind)}, {Label: "state", Value: state}}
		for _, g := range p.Grants {
			value := g.Id
			if g.PublicUrlId != nil {
				value += " " + *g.PublicUrlId
			}
			if g.Namespace != nil {
				value += " " + *g.Namespace
			}
			if g.RevokedAt != nil {
				value += " (revoked)"
			} else if g.ExpiresAt != nil && !g.ExpiresAt.After(time.Now()) {
				value += " (expired)"
			}
			fields = append(fields, clioutput.Field{Label: "grant", Value: value})
		}
		blocks = append(blocks, clioutput.Section(p.Name, clioutput.Fields(fields...)))
	}
	footer := ""
	if page.NextCursor != nil {
		footer = "next: tnl publisher list --after " + *page.NextCursor
	}
	return writeHumanFrame(output, "tnl publisher list", countState(len(page.Identities), "publisher", "publishers"), footer, blocks...)
}

func runPublisherRevoke(ctx context.Context, f publisherRevokeCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(f.ID, opaqueid.PublisherIdentityPrefix) {
		return publisherCLIError("pass a publisher identity ID")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	if err := session.authenticated.Control.RevokePublisherIdentity(ctx, current.team.Id, f.ID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher revoke", "revoked", "active runs stop on heartbeat", clioutput.Fields(clioutput.Field{Label: "publisher", Value: f.ID}))
}

func runPublisherGrantAdd(ctx context.Context, f publisherGrantAddCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(f.PublisherID, opaqueid.PublisherIdentityPrefix) {
		return publisherCLIError("pass a publisher identity ID")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher grant add", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	url, domain, err := publisherCLIScope(current, f.PublicURLID, f.Namespace, f.Domain)
	if err != nil {
		return err
	}
	g, err := session.authenticated.Control.CreatePublisherGrant(ctx, f.PublisherID, controlv1.CreatePublisherGrantRequest{TeamId: current.team.Id, PublicUrlId: url, DomainId: domain})
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher grant add", "created", "", clioutput.Fields(clioutput.Field{Label: "publisher", Value: f.PublisherID}, clioutput.Field{Label: "grant", Value: g.Id}))
}

func runPublisherGrantRevoke(ctx context.Context, f publisherGrantRevokeCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(f.PublisherID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(f.GrantID, opaqueid.PublisherGrantPrefix) {
		return publisherCLIError("pass publisher and grant IDs")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher grant revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	if err := session.authenticated.Control.RevokePublisherGrant(ctx, current.team.Id, f.PublisherID, f.GrantID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher grant revoke", "revoked", "active runs stop on heartbeat", clioutput.Fields(clioutput.Field{Label: "publisher", Value: f.PublisherID}, clioutput.Field{Label: "grant", Value: f.GrantID}))
}
