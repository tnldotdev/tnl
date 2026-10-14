package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherCommand struct {
	Enroll  publisherEnrollCommand  `cmd:"" help:"Issue a one-use publisher enrollment key for a saved URL or authorized namespace."`
	List    publisherListCommand    `cmd:"" help:"List enrolled publishers and their grants in the selected team."`
	Revoke  publisherRevokeCommand  `cmd:"" help:"Revoke a publisher identity and close its active runs on heartbeat."`
	Grant   publisherGrantCommand   `cmd:"" help:"Add or revoke one publisher grant."`
	Service publisherServiceCommand `cmd:"" hidden:""`
	Stop    publisherStopCommand    `cmd:"" help:"Stop background publishing of one public URL on this machine."`
}

type publisherServiceCommand struct {
	Install struct{}                      `cmd:"" hidden:""`
	Serve   publisherServiceServeCommand  `cmd:"" hidden:""`
	Remove  publisherServiceRemoveCommand `cmd:"" hidden:""`
}

type publisherServiceServeCommand struct {
	StateDir string `name:"state-dir" hidden:"" type:"path"`
}

type publisherServiceRemoveCommand struct {
	PublicURLID string `arg:"" name:"public-url-id"`
}

type publisherStopCommand struct {
	PublicURLID string `arg:"" name:"public-url-id"`
}

type enrollmentOutputMode string

const (
	enrollmentOutputHuman enrollmentOutputMode = "human"
	enrollmentOutputRaw   enrollmentOutputMode = "raw"
	enrollmentOutputJSON  enrollmentOutputMode = "json"
)

type publisherEnrollCommand struct {
	scopedTeamFlags `embed:""`
	Selector        string               `arg:"" name:"service-or-public-url-id" optional:"" help:"Configured service or existing saved public URL ID."`
	Name            string               `name:"name" help:"Public URL label and publisher name; for an existing ID, the publisher name."`
	PublisherName   string               `name:"publisher-name" help:"Publisher name when it differs from the public URL label."`
	PublicURL       string               `name:"public-url" help:"Exact hostname or HTTPS origin for a new saved public URL."`
	Domain          string               `name:"domain" help:"Team domain for a new saved public URL."`
	Target          string               `name:"target" help:"HTTP or HTTPS target for a new saved public URL; TCP targets stay on the publisher."`
	Protocol        string               `name:"protocol" help:"Service protocol of a new saved public URL; defaults to http."`
	AllowIP         []string             `name:"allow-ip" help:"Visitor IP address or prefix; repeat for more visitors."`
	AllowAllIPs     bool                 `name:"allow-all-ips" help:"Allow visitors from every IP."`
	Namespace       bool                 `name:"namespace" help:"Grant temporary public URLs within the authorized namespace."`
	Automation      bool                 `name:"automation" help:"Issue a short-lived identity for CI instead of a durable installation."`
	Output          enrollmentOutputMode `name:"output" enum:"human,raw,json" default:"human" help:"Output format: ${enum}."`
}

type publisherEnrollmentResult struct {
	SchemaVersion int       `json:"schema_version"`
	PublicURLID   string    `json:"public_url_id,omitempty"`
	PublicURL     string    `json:"public_url,omitempty"`
	Namespace     string    `json:"namespace,omitempty"`
	TeamID        string    `json:"team_id"`
	Kind          string    `json:"kind"`
	EnrollmentID  string    `json:"enrollment_id"`
	EnrollmentKey string    `json:"enrollment_key"`
	PublisherName string    `json:"publisher_name"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func runPublisherEnroll(ctx context.Context, flags publisherEnrollCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.Namespace {
		return enrollPublisherNamespace(ctx, flags, output, diagnostics)
	}
	protocol, err := publishProtocol(flags.Protocol)
	if err != nil {
		return err
	}
	if protocol != controlv1.Http && flags.Target != "" {
		return failure.Wrap("select publisher target", failure.InvalidTunnelFlags,
			errors.New("TCP targets stay on the publishing device; omit --target and supply host:port when publishing"))
	}
	isURLID := opaqueid.Valid(flags.Selector, opaqueid.PublicURLPrefix)
	if isURLID && (flags.PublicURL != "" || flags.Domain != "" || flags.Target != "" || len(flags.AllowIP) != 0 || flags.AllowAllIPs) {
		return failure.Wrap("select public URL", failure.InvalidTunnelFlags,
			errors.New("an existing public URL ID does not take hostname, target, or visitor policy options"))
	}
	identityName := flags.PublisherName
	if identityName == "" && flags.Name != "" {
		identityName = flags.Name
	}
	selection := flags
	if isURLID {
		selection.Name = ""
	} else {
		selection, err = resolveEnrollmentConfig(selection, project)
		if err != nil {
			return err
		}
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher enroll", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	var route controlv1.PublicURL
	if isURLID {
		route, err = session.authenticated.Control.GetPublicURL(ctx, flags.Selector)
		if err != nil {
			return err
		}
		if route.TeamId != current.team.Id {
			return controlclient.ErrNotFound
		}
	} else {
		route, err = selectEnrollmentURL(ctx, session, selection, protocol)
		if err != nil {
			return err
		}
	}
	if route.Ephemeral || route.Purpose != controlv1.App || route.LifecycleState != controlv1.Enabled ||
		flags.Protocol != "" && route.ServiceProtocol != protocol {
		return failure.Wrap("enroll publisher", failure.ServerConflict,
			errors.New("the selected public URL is not an enabled saved app URL with the selected protocol"))
	}
	if identityName == "" {
		identityName, _, _ = strings.Cut(route.CanonicalHostname, ".")
	}
	if !naming.ValidServiceName(identityName) {
		return failure.Wrap("enroll publisher", failure.InvalidTunnelFlags,
			errors.New("pass --name or --publisher-name with a lowercase publisher name up to 32 characters"))
	}
	address, err := savedPublicAddress(route)
	if err != nil {
		return err
	}
	issued, err := session.authenticated.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{
		TeamId: controlv1.TeamID(route.TeamId), PublicUrlId: &route.Id,
		Kind: enrollmentIdentityKind(flags), Name: identityName,
	})
	if err != nil {
		return err
	}
	if issued.Id == "" || issued.PublicUrlId == nil || string(*issued.PublicUrlId) != route.Id ||
		issued.EnrollmentKey == "" || !issued.ExpiresAt.After(time.Now()) {
		return failure.Wrap("validate publisher enrollment", failure.ServerResponseInvalid,
			errors.New("control returned an invalid publisher enrollment"))
	}
	result := publisherEnrollmentResult{
		SchemaVersion: 1, PublicURLID: route.Id, PublicURL: address, TeamID: route.TeamId,
		Kind: "saved_url", EnrollmentID: issued.Id,
		EnrollmentKey: issued.EnrollmentKey, PublisherName: identityName, ExpiresAt: issued.ExpiresAt,
	}
	return writePublisherEnrollment(flags.Output, result, output, diagnostics)
}

func enrollmentIdentityKind(flags publisherEnrollCommand) controlv1.CreatePublisherEnrollmentRequestKind {
	if flags.Automation {
		return controlv1.CreatePublisherEnrollmentRequestKindAutomation
	}
	return controlv1.CreatePublisherEnrollmentRequestKindInstalled
}

func enrollPublisherNamespace(ctx context.Context, flags publisherEnrollCommand, output, diagnostics io.Writer) error {
	if flags.Selector != "" || flags.PublicURL != "" || flags.Target != "" || flags.Protocol != "" ||
		len(flags.AllowIP) != 0 || flags.AllowAllIPs {
		return failure.Wrap("select publisher namespace", failure.InvalidTunnelFlags,
			errors.New("--namespace selects a team domain, not a saved URL or visitor IP policy"))
	}
	identityName := flags.PublisherName
	if identityName == "" {
		identityName = flags.Name
	}
	if identityName == "" {
		identityName = "namespace-publisher"
	}
	if !naming.ValidServiceName(identityName) {
		return failure.Wrap("select publisher name", failure.InvalidTunnelFlags,
			errors.New("pass a lowercase publisher name up to 32 characters"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher enroll", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.currentWithDomains(ctx)
	if err != nil {
		return err
	}
	domain, err := readyDomain(current, flags.Domain)
	if err != nil {
		return err
	}
	namespace, direct := current.namespace(domain)
	scope := controlv1.Member
	if direct {
		scope = controlv1.Shared
	}
	issued, err := session.authenticated.Control.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{
		TeamId: controlv1.TeamID(current.team.Id), DomainId: &domain.Id,
		PublicUrlScope: &scope, Kind: enrollmentIdentityKind(flags), Name: identityName,
	})
	if err != nil {
		return err
	}
	if issued.Id == "" || issued.Namespace == nil || *issued.Namespace != namespace ||
		issued.EnrollmentKey == "" || !issued.ExpiresAt.After(time.Now()) {
		return failure.Wrap("validate publisher namespace enrollment", failure.ServerResponseInvalid,
			errors.New("control returned a different namespace grant"))
	}
	return writePublisherEnrollment(flags.Output, publisherEnrollmentResult{
		SchemaVersion: 1, TeamID: current.team.Id, Kind: "namespace", Namespace: namespace,
		EnrollmentID: issued.Id, EnrollmentKey: issued.EnrollmentKey,
		PublisherName: identityName, ExpiresAt: issued.ExpiresAt,
	}, output, diagnostics)
}

func writePublisherEnrollment(mode enrollmentOutputMode, result publisherEnrollmentResult, output, diagnostics io.Writer) error {
	if mode == enrollmentOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	if mode == enrollmentOutputRaw {
		_, err := fmt.Fprintln(output, result.EnrollmentKey)
		return err
	}
	fields := []clioutput.Field{{Label: "publisher", Value: result.PublisherName},
		{Label: "expires", Value: result.ExpiresAt.UTC().Format(time.RFC3339)}}
	if result.Kind == "saved_url" {
		fields = append([]clioutput.Field{{Label: "public URL", Value: result.PublicURL},
			{Label: "URL ID", Value: result.PublicURLID}}, fields...)
	} else {
		fields = append([]clioutput.Field{{Label: "namespace", Value: result.Namespace}}, fields...)
	}
	if err := writeHumanFrame(diagnostics, "tnl publisher enroll", "created", "use the enrollment key once on the publishing device",
		clioutput.Fields(fields...)); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, "enrollment key: "+result.EnrollmentKey)
	return err
}
