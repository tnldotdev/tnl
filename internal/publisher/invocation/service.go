package invocation

import (
	"context"
	"errors"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// realize only the selected local service. remote targets and trust sources are
// never evaluated or applied as a side effect of starting a development app.
type LocalService struct {
	Project          clientproject.Project
	Team             TeamSelection
	Name             string
	Domain           string
	PreviewPublisher string
	TargetResolver   target.TargetResolver
}

func RealizeLocalService(ctx context.Context, control *clientcontrol.Client, selected LocalService) (controlv1.LocalProjectService, error) {
	project := projectConfiguration{Project: selected.Project, targetResolver: selected.TargetResolver}
	current, name := selected.Team, selected.Name
	source := project.LocalPublicationIdentity()
	if source.Key == "" || project.LocalWorktreeKey() == "" {
		return controlv1.LocalProjectService{}, failure.Wrap("identify local service", failure.ClientStateUnavailable, errors.New("project is not bound to client state"))
	}
	declaration, err := resolve.Declaration(ctx, project.Project, current.Context(), func(ctx context.Context, name string) (string, error) {
		resolver := project.targetResolver
		if resolver == nil {
			resolver = target.Resolver{}
		}
		address, _, err := resolver.ResolveTargetIdentity(ctx, project.Project, name)
		return address, err
	}, name)
	if err != nil {
		return controlv1.LocalProjectService{}, err
	}
	request := controlv1.RealizeLocalProjectServiceRequest{TeamId: current.team.Id, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(), Configuration: declaration.Services[name]}
	if selected.PreviewPublisher != "" {
		if selected.Domain != "" || request.Configuration.DomainId != nil || request.Configuration.Hostname != nil || request.Configuration.PublisherAliasParent != nil {
			return controlv1.LocalProjectService{}, failure.Wrap("select opaque naming", failure.ProjectConfigInvalid, errors.New("opaque naming cannot be combined with a domain, hostname, or publisher alias"))
		}
		request.PreviewPublisherId = &selected.PreviewPublisher
	}
	label := project.Worktree.Label.FullLabel
	if current.Context().Mode() == naming.ManagedURLModeGenerated {
		label = naming.ProjectDNSLabel(project.Worktree.Label.Project, project.Worktree.Label.Checkout)
	}
	if label != "" {
		request.WorktreeLabel = &label
	}
	if selected.Domain != "" {
		domain, err := current.Context().ReadyDomain(selected.Domain)
		if err != nil {
			return controlv1.LocalProjectService{}, err
		}
		request.Configuration.DomainId = &domain.Id
	}
	realized, err := control.RealizeLocalProjectService(ctx, source.Key, name, request)
	if err != nil {
		return controlv1.LocalProjectService{}, err
	}
	if realized.Service != name || realized.WorktreeKey != request.WorktreeKey || !opaqueid.Valid(realized.ServiceId, opaqueid.ServicePrefix) {
		return controlv1.LocalProjectService{}, failure.Wrap("realize local project service", failure.ServerResponseInvalid, errors.New("control returned another local project service"))
	}
	return realized, nil
}
