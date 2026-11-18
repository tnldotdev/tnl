package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherCommand struct {
	Serve     publisherServeCommand     `cmd:"" help:"Run this replica's assigned services with a saved or portable deployment identity."`
	Current   publisherCurrentCommand   `cmd:"" help:"Show the selected local or file-backed publisher without exposing its key."`
	Setup     publisherSetupCommand     `cmd:"" help:"Approve scoped deployment publisher enrollment or set up a local publisher."`
	Provision publisherProvisionCommand `cmd:"" help:"Write a portable scoped publisher file for deployment."`
	Enroll    publisherEnrollCommand    `cmd:"" help:"Issue one-use enrollment for an exact service or HTTP namespace."`
	List      publisherListCommand      `cmd:"" help:"List publisher identities and grants."`
	Revoke    publisherRevokeCommand    `cmd:"" help:"Revoke a publisher identity."`
	Grant     struct {
		Add    publisherGrantAddCommand    `cmd:"" help:"Add an exact service or HTTP namespace grant."`
		Revoke publisherGrantRevokeCommand `cmd:"" help:"Revoke one publisher grant."`
	} `cmd:"" help:"Manage publisher grants."`
}
type publisherSetupCommand struct {
	scopedTeamFlags `embed:""`
	Deployment      string           `name:"deployment" help:"Saved deployment name or ID for bounded publisher enrollment."`
	ProjectKey      string           `name:"project-key" help:"Applied project key; defaults to this Git configuration source."`
	Services        []string         `name:"service" help:"Service name to approve with --deployment; repeat for several. Without --deployment, selects one exact saved service ID."`
	Members         int              `name:"members" default:"1" help:"Lifetime enrollments admitted by this deployment key; bounded by the server ceiling."`
	ExpiresIn       time.Duration    `name:"expires-in" default:"10m" help:"Deployment enrollment-key lifetime (1m-8760h), bounded by the server ceiling."`
	IdempotencyKey  string           `name:"idempotency-key" help:"Original deployment setup request key for lost-response recovery."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"With --deployment, print a raw enrollment key with human diagnostics, or JSON containing the key."`
	Namespace       bool             `help:"Set up this team's HTTP namespace for local application publication."`
	URL             string           `name:"url" help:"Set up one exact service by ID or public address."`
	Domain          string           `help:"Ready team domain; defaults to the team's default domain."`
}
type publisherProvisionCommand struct {
	scopedTeamFlags `embed:""`
	Deployment      string   `name:"deployment" help:"Configured deployment for one replica's portable signing identity."`
	ProjectKey      string   `name:"project-key" help:"Applied project key for a deployment identity; defaults to this Git configuration source."`
	Instance        string   `name:"instance" help:"Replica identity name; required with --deployment and bound into the private file."`
	Namespace       bool     `help:"Grant temporary HTTP URLs in your namespace."`
	URL             string   `name:"url" help:"Service ID or public address for an exact grant."`
	ServiceID       string   `name:"service-id" help:"Saved service ID for an exact grant without --deployment."`
	Services        []string `name:"service" help:"Exact binding name to approve with --deployment; repeat for multiple bindings."`
	Domain          string   `help:"Ready team domain for a namespace grant."`
	OutputFile      string   `name:"output-file" type:"path" required:"" help:"New private file for deployment; never overwrites an existing file."`
}

func (f publisherProvisionCommand) Validate() error {
	if len(f.Services) != 0 && f.Deployment == "" {
		return publisherCLIError("--service requires --deployment; use --service-id for one exact saved service")
	}
	return nil
}

func runPublisherSetup(ctx context.Context, f publisherSetupCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if f.Deployment != "" {
		return runDeploymentPublisherSetup(ctx, f, project, output, diagnostics)
	}
	if f.ProjectKey != "" || f.IdempotencyKey != "" || f.Output == statusOutputJSON || f.Members != 1 || f.ExpiresIn != 10*time.Minute {
		return publisherCLIError("--project-key, --idempotency-key, --output json, --members, and --expires-in require --deployment")
	}
	if len(f.Services) > 0 {
		if len(f.Services) != 1 || !opaqueid.Valid(f.Services[0], opaqueid.ServicePrefix) {
			return publisherCLIError("select one exact saved service ID without --deployment")
		}
		if f.Namespace || f.URL != "" || f.Domain != "" {
			return publisherCLIError("select --namespace, --url, or --service")
		}
		f.URL = f.Services[0]
	}
	if f.Namespace == (f.URL != "") || !f.Namespace && f.Domain != "" {
		return publisherCLIError("select --namespace or --url <service-id-or-address> for local setup")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher setup", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if f.URL != "" {
		service, err := managedService(ctx, session, f.URL)
		if err != nil {
			return err
		}
		n, identity, err := publisheridentity.EnsureServiceOwner(ctx, session.Store(), session.Authenticated().Control, session.Authenticated().Authority, service)
		if err != nil {
			return err
		}
		if _, err := n.SavedService(ctx); err != nil {
			return err
		}
		return writeHumanFrame(output, "tnl publisher setup", "ready", "service publisher is set up", clioutput.Fields(
			clioutput.Field{Label: "service ID", Value: service.Id}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId},
		))
	}
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		return err
	}
	domain, err := current.ReadyDomain(f.Domain)
	if err != nil {
		return err
	}
	namespace, valid := current.Namespace(domain)
	if !valid || namespace == "" {
		return publisherCLIError("selected domain has no HTTP namespace")
	}
	_, identity, err := publisheridentity.EnsureNamespace(ctx, session.Store(), session.Authenticated().Control, session.Authenticated().Authority, current.Team().Id, domain.Id, namespace)
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher setup", "ready", "local apps can now publish in this namespace", clioutput.Fields(
		clioutput.Field{Label: "namespace", Value: namespace}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId},
	))
}

func runPublisherProvision(ctx context.Context, f publisherProvisionCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if err := f.Validate(); err != nil {
		return err
	}
	if f.Deployment != "" {
		if f.Namespace || f.URL != "" || f.ServiceID != "" || f.Domain != "" || len(f.Services) == 0 {
			return publisherCLIError("select --deployment, --namespace, --url, or --service")
		}
		return runDeploymentPublisherProvision(ctx, deploymentIdentityProvisionOptions{Remote: f.selection(), Deployment: f.Deployment, ProjectKey: f.ProjectKey, Instance: f.Instance, OutputFile: f.OutputFile, Services: f.Services}, project, output, diagnostics)
	}
	if f.ProjectKey != "" || f.Instance != "" {
		return publisherCLIError("--project-key and --instance require --deployment")
	}
	if f.OutputFile == "" {
		return publisherCLIError("pass --output-file for the portable publisher identity")
	}
	if _, err := os.Lstat(f.OutputFile); err == nil {
		return credentialfile.ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return credentialfile.ErrInvalid
	}
	if f.ServiceID != "" {
		if f.Namespace || f.URL != "" || f.Domain != "" || !opaqueid.Valid(f.ServiceID, opaqueid.ServicePrefix) {
			return publisherCLIError("select --namespace, --url, or --service")
		}
		f.URL = f.ServiceID
	}
	if f.Namespace == (f.URL != "") || !f.Namespace && f.Domain != "" {
		return publisherCLIError("select --namespace or --url <service-id-or-address>")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher provision", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := publisherScopeTeam(ctx, session, f.Namespace)
	if err != nil {
		return err
	}
	service, domain, err := publisherCLIGrantScope(ctx, session, current, f.URL, "", f.Namespace, f.Domain)
	if err != nil {
		return err
	}
	var namespace string
	if domain != nil {
		d, err := current.ReadyDomain(f.Domain)
		if err != nil {
			return err
		}
		var valid bool
		namespace, valid = current.Namespace(d)
		if !valid || namespace == "" {
			return publisherCLIError("selected domain has no HTTP namespace")
		}
	}
	e, err := session.Authenticated().Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: current.Team().Id, ServiceId: service, DomainId: domain, Name: "deployment", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
	if err != nil {
		return err
	}
	if !opaqueid.Valid(e.Id, opaqueid.PublisherEnrollmentPrefix) || !strings.HasPrefix(e.EnrollmentKey, e.Id+".") || e.TeamId != current.Team().Id || !e.ExpiresAt.After(time.Now()) || service != nil && (e.Kind != "service" || e.ServiceId == nil || *e.ServiceId != *service || e.DomainId != nil || e.Namespace != nil) || domain != nil && (e.Kind != "namespace" || e.ServiceId != nil || e.DomainId == nil || *e.DomainId != *domain || e.Namespace == nil || *e.Namespace != namespace) {
		return failure.Wrap("read publisher enrollment", failure.ServerResponseInvalid, errors.New("control returned a different publisher scope"))
	}
	capabilities := publisheridentity.NativeControl{Services: session.Authenticated().Control}
	if domain != nil {
		capabilities.Allocations = session.Authenticated().Control
	}
	n, identity, err := publisheridentity.EnrollNative(ctx, session.Store(), capabilities, session.Authenticated().Authority, e.EnrollmentKey)
	if err != nil {
		return err
	}
	if identity.TeamId != current.Team().Id || service != nil && (identity.Kind != "service" || identity.ServiceId == nil || *identity.ServiceId != *service || identity.DomainId != nil || identity.Namespace != nil) || domain != nil && (identity.Kind != "namespace" || identity.ServiceId != nil || identity.DomainId == nil || *identity.DomainId != *domain || identity.Namespace == nil || *identity.Namespace != namespace) {
		return publisheridentity.ErrScope
	}
	if service != nil {
		_, err = n.SavedService(ctx)
	} else {
		_, err = n.Access(ctx)
	}
	if err != nil {
		return err
	}
	_, signing, err := invocation.SigningIdentity(ctx, session.Store(), identity.ClientId)
	if err != nil {
		return err
	}
	fCred, err := credentialfile.New(session.Authenticated().ServerEndpoint, identity, signing)
	if err != nil {
		return err
	}
	if err := credentialfile.Write(f.OutputFile, fCred); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher provision", "created", "mount the file and set TNL_PUBLISHER_CREDENTIAL_FILE", clioutput.Fields(
		clioutput.Field{Label: "file", Value: f.OutputFile}, clioutput.Field{Label: "publisher", Value: identity.ClientId}, clioutput.Field{Label: "grant", Value: identity.GrantId},
	))
}

type publisherEnrollCommand struct {
	scopedTeamFlags `embed:""`
	Address         string `arg:"" optional:"" name:"service-or-address" help:"Enabled service ID or public address."`
	ServiceID       string `name:"service" help:"Exact saved service ID."`
	Name            string `default:"publisher" help:"Lowercase publisher name."`
	Namespace       bool   `help:"Grant temporary HTTP URLs in your authorized namespace."`
	Domain          string `help:"Ready team domain for namespace enrollment."`
	Automation      bool   `help:"Expire the initial grant after one hour."`
}
type publisherListCommand struct {
	scopedTeamFlags `embed:""`
	Deployment      string           `name:"deployment" help:"List only publishers belonging to this saved deployment."`
	ProjectKey      string           `name:"project-key" help:"Applied project key with --deployment; defaults to this Git configuration source."`
	Limit           int              `name:"limit" default:"50" help:"Deployment publishers per page, from 1 to 100."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
	After           string           `help:"Continue after this publisher identity ID."`
}
type publisherRevokeCommand struct {
	scopedTeamFlags `embed:""`
	Deployment      string           `name:"deployment" help:"Require this saved deployment's ownership before revoking."`
	ProjectKey      string           `name:"project-key" help:"Applied project key with --deployment; defaults to this Git configuration source."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
	ID              string           `arg:"" name:"publisher-identity-id"`
}
type publisherGrantAddCommand struct {
	scopedTeamFlags     `embed:""`
	PublisherIdentityID string `arg:"" name:"publisher-identity-id"`
	URL                 string `name:"url" help:"Public hostname or HTTPS origin of the service to grant."`
	ServiceID           string `name:"service" help:"Exact saved service ID to grant."`
	Namespace           bool   `help:"Grant temporary HTTP URLs in your namespace."`
	Domain              string `help:"Ready team domain for a namespace grant."`
}
type publisherGrantRevokeCommand struct {
	scopedTeamFlags     `embed:""`
	PublisherIdentityID string `arg:"" name:"publisher-identity-id"`
	GrantID             string `arg:"" name:"grant-id"`
}

func publisherCLIError(message string) error {
	return failure.Wrap("select publisher identity", failure.InvalidTunnelFlags, errors.New(message))
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
	current, err := publisherScopeTeam(ctx, session, f.Namespace)
	if err != nil {
		return err
	}
	service, domain, err := publisherCLIGrantScope(ctx, session, current, f.Address, f.ServiceID, f.Namespace, f.Domain)
	if err != nil {
		return err
	}
	kind := controlv1.CreatePublisherEnrollmentRequestKindInstalled
	if f.Automation {
		kind = controlv1.CreatePublisherEnrollmentRequestKindAutomation
	}
	e, err := session.Authenticated().Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: current.Team().Id, DomainId: domain, ServiceId: service, Name: f.Name, Kind: kind})
	if err != nil {
		return err
	}
	if !opaqueid.Valid(e.Id, opaqueid.PublisherEnrollmentPrefix) || !strings.HasPrefix(e.EnrollmentKey, e.Id+".") || !e.ExpiresAt.After(time.Now()) || e.TeamId != current.Team().Id || service != nil && (e.Kind != "service" || e.ServiceId == nil || *e.ServiceId != *service || e.DomainId != nil || e.Namespace != nil) || domain != nil && (e.Kind != "namespace" || e.DomainId == nil || *e.DomainId != *domain || e.ServiceId != nil || !publisherNamespaceMatches(current, *domain, e.Namespace)) {
		return failure.Wrap("read publisher enrollment", failure.ServerResponseInvalid, errors.New("control returned a different enrollment"))
	}
	// one-use enrollment secrets remain exact raw values on stdout.
	_, err = fmt.Fprintln(output, e.EnrollmentKey)
	return err
}

func runPublisherList(ctx context.Context, f publisherListCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if f.Deployment != "" {
		return runDeploymentPublisherList(ctx, f, project, output, diagnostics)
	}
	if f.ProjectKey != "" || f.Limit != 50 {
		return publisherCLIError("--project-key and --limit require --deployment")
	}
	if f.After != "" && !opaqueid.Valid(f.After, opaqueid.PublisherIdentityPrefix) {
		return publisherCLIError("--after requires a publisher identity ID")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	page, err := session.Authenticated().Control.ListPublisherIdentities(ctx, current.Team().Id, f.After)
	if err != nil {
		return err
	}
	if f.Output == statusOutputJSON {
		return failure.Wrap("write publishers", failure.OutputUnavailable, json.NewEncoder(output).Encode(page))
	}
	blocks := []clioutput.Block{}
	for _, p := range page.Identities {
		state := "active"
		if p.RevokedAt != nil {
			state = "revoked"
		}
		fields := []clioutput.Field{{Label: "publisher", Value: p.Id}, {Label: "kind", Value: string(p.Kind)}, {Label: "state", Value: state}}
		fields = append(fields, publisherRuntimeFields(p.Runtime)...)
		for _, g := range p.Grants {
			value := g.Id
			if g.Namespace != nil {
				value += " " + *g.Namespace
			}
			if g.ServiceId != nil {
				value += " " + *g.ServiceId
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

func runPublisherRevoke(ctx context.Context, f publisherRevokeCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if f.Deployment != "" {
		return runDeploymentPublisherRevoke(ctx, f, project, output, diagnostics)
	}
	if f.ProjectKey != "" {
		return publisherCLIError("--project-key requires --deployment")
	}
	if !opaqueid.Valid(f.ID, opaqueid.PublisherIdentityPrefix) {
		return publisherCLIError("pass a publisher identity ID")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	if err := session.Authenticated().Control.RevokePublisherIdentity(ctx, current.Team().Id, f.ID); err != nil {
		return err
	}
	if f.Output == statusOutputJSON {
		return writePublisherRevoked(output, f.ID)
	}
	return writeHumanFrame(output, "tnl publisher revoke", "revoked", "active runs stop on heartbeat", clioutput.Fields(clioutput.Field{Label: "publisher", Value: f.ID}))
}

func runPublisherGrantAdd(ctx context.Context, f publisherGrantAddCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(f.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) {
		return publisherCLIError("pass a publisher identity ID")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher grant add", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := publisherScopeTeam(ctx, session, f.Namespace)
	if err != nil {
		return err
	}
	service, domain, err := publisherCLIGrantScope(ctx, session, current, f.URL, f.ServiceID, f.Namespace, f.Domain)
	if err != nil {
		return err
	}
	g, err := session.Authenticated().Control.CreatePublisherGrant(ctx, f.PublisherIdentityID, controlv1.CreatePublisherGrantRequest{TeamId: current.Team().Id, DomainId: domain, ServiceId: service})
	if err != nil {
		return err
	}
	if g.TeamId != current.Team().Id || service != nil && (g.Kind != "service" || g.ServiceId == nil || *g.ServiceId != *service || g.DomainId != nil || g.Namespace != nil) || domain != nil && (g.Kind != "namespace" || g.DomainId == nil || *g.DomainId != *domain || g.ServiceId != nil || !publisherNamespaceMatches(current, *domain, g.Namespace)) {
		return publisheridentity.ErrScope
	}
	return writeHumanFrame(output, "tnl publisher grant add", "created", "", clioutput.Fields(clioutput.Field{Label: "publisher", Value: f.PublisherIdentityID}, clioutput.Field{Label: "grant", Value: g.Id}))
}

func publisherScopeTeam(ctx context.Context, session *clientteam.Session, namespace bool) (clientteam.Context, error) {
	if namespace {
		return session.CurrentWithDomains(ctx)
	}
	return session.Current(ctx)
}

func publisherCLIGrantScope(ctx context.Context, session *clientteam.Session, current clientteam.Context, address, serviceID string, namespace bool, domain string) (*string, *string, error) {
	selections := 0
	for _, selected := range []bool{address != "", serviceID != "", namespace} {
		if selected {
			selections++
		}
	}
	if selections != 1 || !namespace && domain != "" || serviceID != "" && !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) {
		return nil, nil, publisherCLIError("select an exact service ID or public address, or --namespace")
	}
	if namespace {
		d, err := current.ReadyDomain(domain)
		if err != nil {
			return nil, nil, err
		}
		if expected, valid := current.Namespace(d); !valid || expected == "" {
			return nil, nil, publisherCLIError("selected domain has no HTTP namespace")
		}
		return nil, &d.Id, nil
	}
	if serviceID == "" {
		serviceID = address
	}
	service, err := managedService(ctx, session, serviceID)
	if err != nil {
		return nil, nil, err
	}
	if !service.Enabled || service.TeamId != current.Team().Id {
		return nil, nil, publisheridentity.ErrScope
	}
	return &service.Id, nil, nil
}

func managedService(ctx context.Context, session *clientteam.Session, selector string) (controlv1.Service, error) {
	id := selector
	if !opaqueid.Valid(id, opaqueid.ServicePrefix) {
		selected, err := resolveManagedService(ctx, session, selector)
		if err != nil {
			return controlv1.Service{}, err
		}
		id = selected.Id
	}
	current, err := session.Current(ctx)
	if err != nil {
		return controlv1.Service{}, err
	}
	service, err := session.Authenticated().Control.GetService(ctx, id)
	if err != nil {
		return service, err
	}
	if service.Id != id || service.TeamId != current.Team().Id || !service.Enabled {
		return service, publisheridentity.ErrScope
	}
	_, err = publisheridentity.ServiceTrust(service)
	return service, err
}

func publisherNamespaceMatches(current clientteam.Context, domainID string, namespace *string) bool {
	domain, err := current.ReadyDomain(domainID)
	if err != nil || namespace == nil {
		return false
	}
	expected, valid := current.Namespace(domain)
	return valid && expected != "" && *namespace == expected
}

func runPublisherGrantRevoke(ctx context.Context, f publisherGrantRevokeCommand, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(f.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(f.GrantID, opaqueid.PublisherGrantPrefix) {
		return publisherCLIError("pass publisher and grant IDs")
	}
	session, err := openTeamSession(ctx, f.selection(), "tnl publisher grant revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	if err := session.Authenticated().Control.RevokePublisherGrant(ctx, current.Team().Id, f.PublisherIdentityID, f.GrantID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher grant revoke", "revoked", "active runs stop on heartbeat", clioutput.Fields(clioutput.Field{Label: "publisher", Value: f.PublisherIdentityID}, clioutput.Field{Label: "grant", Value: f.GrantID}))
}
