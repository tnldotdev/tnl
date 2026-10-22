package invocation

import (
	"context"
	"errors"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// realize only the selected local service. remote targets and trust sources are
// never evaluated or applied as a side effect of starting a development app.
type LocalService struct {
	Project        clientproject.Project
	Team           TeamSelection
	Name           string
	PublicURLID    string
	Domain         string
	TargetResolver target.TargetResolver
}

func RealizeLocalService(ctx context.Context, control *clientcontrol.Client, selected LocalService) (controlv1.LocalProjectService, error) {
	project := projectConfiguration{Project: selected.Project, targetResolver: selected.TargetResolver}
	current, name, publicURLID := selected.Team, selected.Name, selected.PublicURLID
	source := project.LocalPublicationIdentity()
	declaration, err := resolve.Declaration(ctx, project.Project, current.Context(), func(ctx context.Context, name string) (string, error) {
		resolver := project.targetResolver
		if resolver == nil {
			resolver = target.Resolver{}
		}
		resolved, err := target.ResolveTarget(ctx, project.Project, name, resolver)
		if err != nil {
			return "", err
		}
		return string(*resolved.Target), nil
	}, name)
	if err != nil {
		return controlv1.LocalProjectService{}, err
	}
	request := controlv1.RealizeLocalProjectServiceRequest{TeamId: current.team.Id, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(), Configuration: declaration.Services[name]}
	label := project.Worktree.Label.FullLabel
	if label != "" {
		request.WorktreeLabel = &label
	}
	if selected.Domain != "" {
		domain, err := current.Context().ReadyDomain(selected.Domain)
		if err != nil {
			return controlv1.LocalProjectService{}, err
		}
		request.DomainId = &domain.Id
	}
	if publicURLID != "" {
		request.PublicUrlId = &publicURLID
	}
	realized, err := control.RealizeLocalProjectService(ctx, source.Key, name, request)
	if err != nil {
		return controlv1.LocalProjectService{}, err
	}
	kind := "service"
	if publicURLID != "" {
		kind = "public_url"
	}
	if realized.Service != name || realized.WorktreeKey != request.WorktreeKey || string(realized.ServiceKind) != kind || realized.ServiceId == "" || publicURLID != "" && realized.ServiceId != publicURLID {
		return controlv1.LocalProjectService{}, failure.Wrap("realize local project service", failure.ServerResponseInvalid, errors.New("control returned another local project service"))
	}
	return realized, nil
}
