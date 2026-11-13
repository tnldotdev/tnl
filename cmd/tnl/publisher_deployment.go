package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func deploymentPublisherSession(ctx context.Context, flags scopedTeamFlags, project projectConfiguration, key, selector, command string, diagnostics io.Writer) (*clientteam.Session, controlv1.Deployment, error) {
	if !validDeploymentSelector(selector) {
		return nil, controlv1.Deployment{}, publisherCLIError("select a saved deployment name or ID, not local")
	}
	key, err := deploymentProjectKey(ctx, project, key)
	if err != nil {
		return nil, controlv1.Deployment{}, err
	}
	session, err := openTeamSession(ctx, flags.selection(), command, diagnostics)
	if err != nil {
		return nil, controlv1.Deployment{}, err
	}
	current, err := session.Current(ctx)
	if err != nil {
		_ = session.Close()
		return nil, controlv1.Deployment{}, err
	}
	deployment, err := session.Authenticated().Control.GetDeployment(ctx, current.Team().Id, key, selector)
	if err == nil {
		err = validateDeploymentResult(deployment, current.Team().Id, key)
	}
	if err != nil {
		_ = session.Close()
		return nil, controlv1.Deployment{}, err
	}
	return session, deployment, nil
}

func deploymentPublisherSetupBody(flags publisherSetupCommand) (controlv1.CreateDeploymentPublisherEnrollmentRequest, error) {
	invalid := func() (controlv1.CreateDeploymentPublisherEnrollmentRequest, error) {
		return controlv1.CreateDeploymentPublisherEnrollmentRequest{}, publisherCLIError("select --deployment and unique --service names, --members 1-256, and whole-second --expires-in from 1m to 24h; omit namespace, URL, and domain flags")
	}
	if flags.Namespace || flags.URL != "" || flags.Domain != "" || len(flags.Services) < 1 || len(flags.Services) > 128 || flags.Members < 1 || flags.Members > 256 || flags.ExpiresIn < time.Minute || flags.ExpiresIn > 24*time.Hour || flags.ExpiresIn%time.Second != 0 {
		return invalid()
	}
	seen := map[string]bool{}
	for _, name := range flags.Services {
		if !naming.ValidServiceName(name) || seen[name] {
			return invalid()
		}
		seen[name] = true
	}
	if len(flags.IdempotencyKey) > 128 || strings.ContainsAny(flags.IdempotencyKey, "\x00\r\n") {
		return invalid()
	}
	expires, members := int(flags.ExpiresIn/time.Second), flags.Members
	return controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: slices.Clone(flags.Services), MaxMembers: &members, ExpiresIn: &expires}, nil
}

func runDeploymentPublisherSetup(ctx context.Context, flags publisherSetupCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	body, err := deploymentPublisherSetupBody(flags)
	if err != nil {
		return err
	}
	session, deployment, err := deploymentPublisherSession(ctx, flags.scopedTeamFlags, project, flags.ProjectKey, flags.Deployment, "tnl publisher setup", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	services := map[string]controlv1.ServiceProtocol{}
	for _, name := range body.Services {
		service, found := deployment.Services[name]
		if !found {
			return publisherCLIError("every --service must name an existing binding in the selected deployment")
		}
		services[name] = service.Protocol
	}
	key := flags.IdempotencyKey
	if key == "" {
		key, err = randomIdempotencyKey()
		if err != nil {
			return err
		}
	}
	enrollment, err := session.Authenticated().Control.CreateDeploymentPublisherEnrollment(ctx, deployment.TeamId, deployment.ProjectKey, deployment.Id, key, body)
	if err != nil {
		return err
	}
	if err := validateDeploymentPublisherEnrollment(enrollment, deployment.Id, *body.MaxMembers, services, time.Now()); err != nil {
		return err
	}
	return writeDeploymentPublisherEnrollment(output, diagnostics, flags.Output, enrollment)
}

func validateDeploymentPublisherEnrollment(enrollment controlv1.DeploymentPublisherEnrollment, deployment string, members int, services map[string]controlv1.ServiceProtocol, now time.Time) error {
	if enrollment.GroupId != deployment || !opaqueid.Valid(enrollment.EnrollmentId, opaqueid.PublisherEnrollmentPrefix) || !strings.HasPrefix(enrollment.EnrollmentKey, enrollment.EnrollmentId+".") || len(enrollment.EnrollmentKey) <= len(enrollment.EnrollmentId)+1 || strings.ContainsAny(enrollment.EnrollmentKey, "\x00\r\n") || enrollment.MaxMembers != members || !enrollment.ExpiresAt.After(now) || !maps.Equal(enrollment.Services, services) {
		return failure.Wrap("read deployment enrollment", failure.ServerResponseInvalid, errors.New("control returned a different or invalid publisher approval"))
	}
	return nil
}

func writeDeploymentPublisherEnrollment(output, diagnostics io.Writer, mode statusOutputMode, enrollment controlv1.DeploymentPublisherEnrollment) error {
	if mode == statusOutputJSON {
		return failure.Wrap("write deployment enrollment", failure.OutputUnavailable, json.NewEncoder(output).Encode(enrollment))
	}
	fields := []clioutput.Field{{Label: "deployment", Value: enrollment.GroupId}, {Label: "enrollment", Value: enrollment.EnrollmentId}, {Label: "expires", Value: enrollment.ExpiresAt.UTC().Format(time.RFC3339)}, {Label: "publishers", Value: strconv.Itoa(enrollment.MaxMembers)}}
	for _, name := range slices.Sorted(maps.Keys(enrollment.Services)) {
		fields = append(fields, clioutput.Field{Label: name, Value: string(enrollment.Services[name])})
	}
	if err := writeHumanFrame(diagnostics, "tnl publisher setup", "approved", "deliver stdout privately; enrollment does not start a publisher", clioutput.Fields(fields...)); err != nil {
		return err
	}
	_, err := fmt.Fprintln(output, enrollment.EnrollmentKey)
	return failure.Wrap("write deployment enrollment", failure.OutputUnavailable, err)
}

func runDeploymentPublisherList(ctx context.Context, flags publisherListCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.Limit < 1 || flags.Limit > 100 || flags.After != "" && !opaqueid.Valid(flags.After, opaqueid.PublisherIdentityPrefix) {
		return publisherCLIError("select --limit 1-100 and an optional publisher ID with --after")
	}
	session, deployment, err := deploymentPublisherSession(ctx, flags.scopedTeamFlags, project, flags.ProjectKey, flags.Deployment, "tnl publisher list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	page, err := session.Authenticated().Control.ListDeploymentPublishers(ctx, deployment.TeamId, deployment.ProjectKey, deployment.Id, flags.After, flags.Limit)
	if err != nil {
		return err
	}
	if len(page.Publishers) > flags.Limit || page.NextCursor != nil && !opaqueid.Valid(*page.NextCursor, opaqueid.PublisherIdentityPrefix) {
		return failure.Wrap("read deployment publishers", failure.ServerResponseInvalid, errors.New("control returned an invalid publisher page"))
	}
	for _, publisher := range page.Publishers {
		if err := validateDeploymentPublisher(publisher, deployment); err != nil {
			return err
		}
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write deployment publishers", failure.OutputUnavailable, json.NewEncoder(output).Encode(page))
	}
	blocks := []clioutput.Block{}
	for _, publisher := range page.Publishers {
		blocks = append(blocks, deploymentPublisherBlock(publisher))
	}
	if page.NextCursor != nil {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "next cursor", Value: *page.NextCursor}))
	}
	return writeHumanFrame(output, "tnl publisher list", countState(len(page.Publishers), "publisher", "publishers"), "observations do not prove target reachability or a database query", blocks...)
}

func validateDeploymentPublisher(publisher controlv1.DeploymentPublisher, deployment controlv1.Deployment) error {
	invalid := publisher.GroupId != deployment.Id || publisher.TeamId != deployment.TeamId || publisher.ProjectKey != deployment.ProjectKey || !opaqueid.Valid(publisher.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || publisher.SnapshotAt.IsZero() || len(publisher.Services) > 128
	for name, protocol := range publisher.Services {
		invalid = invalid || !naming.ValidServiceName(name) || !protocol.Valid()
	}
	if invalid {
		return failure.Wrap("read deployment publisher", failure.ServerResponseInvalid, errors.New("control returned a different or invalid deployment publisher"))
	}
	return nil
}

func deploymentPublisherBlock(publisher controlv1.DeploymentPublisher) clioutput.Block {
	state := "acknowledgement or lease not current"
	if publisher.Healthy {
		state = "acknowledged with current lease"
	}
	if publisher.RevokedAt != nil {
		state = "revoked"
	}
	fields := []clioutput.Field{{Label: "deployment", Value: publisher.GroupId}, {Label: "state", Value: state}, {Label: "current revision", Value: strconv.FormatInt(publisher.CurrentRevision, 10)}, {Label: "observed revision", Value: strconv.FormatInt(publisher.ObservedRevision, 10)}, {Label: "snapshot", Value: publisher.SnapshotAt.UTC().Format(time.RFC3339)}}
	if publisher.AcknowledgedAt != nil {
		fields = append(fields, clioutput.Field{Label: "acknowledged at", Value: publisher.AcknowledgedAt.UTC().Format(time.RFC3339)})
	}
	if publisher.LeaseExpiresAt != nil {
		fields = append(fields, clioutput.Field{Label: "lease expires", Value: publisher.LeaseExpiresAt.UTC().Format(time.RFC3339)})
	}
	fields = append(fields, publisherRuntimeFields(publisher.Runtime)...)
	for _, name := range slices.Sorted(maps.Keys(publisher.Services)) {
		fields = append(fields, clioutput.Field{Label: name, Value: string(publisher.Services[name])})
	}
	return clioutput.Section(publisher.PublisherIdentityId, clioutput.Fields(fields...))
}

func runDeploymentPublisherRevoke(ctx context.Context, flags publisherRevokeCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(flags.ID, opaqueid.PublisherIdentityPrefix) {
		return publisherCLIError("pass a publisher identity ID")
	}
	session, deployment, err := deploymentPublisherSession(ctx, flags.scopedTeamFlags, project, flags.ProjectKey, flags.Deployment, "tnl publisher revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if err = session.Authenticated().Control.RevokeDeploymentPublisher(ctx, deployment.TeamId, deployment.ProjectKey, deployment.Id, flags.ID); err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return writePublisherRevoked(output, flags.ID)
	}
	return writeHumanFrame(output, "tnl publisher revoke", "revoked", "active publications stop when current authority is refreshed", clioutput.Fields(clioutput.Field{Label: "deployment", Value: deployment.Id}, clioutput.Field{Label: "publisher", Value: flags.ID}))
}

func writePublisherRevoked(output io.Writer, id string) error {
	return failure.Wrap("write publisher revocation", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
		ID      string `json:"publisher_identity_id"`
		Revoked bool   `json:"revoked"`
	}{id, true}))
}
