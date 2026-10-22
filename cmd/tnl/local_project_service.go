package main

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// realize only the selected local service. remote targets and trust sources are
// never evaluated or applied as a side effect of starting a development app.
func realizeLocalService(ctx context.Context, control *controlclient.Client, project projectConfiguration, current teamContext, name, publicURLID string, domainName ...string) (controlv1.LocalProjectService, error) {
	source := project.LocalPublicationIdentity()
	declaration, err := projectDeclaration(ctx, project, current, projectconfig.SourceIdentity{}, name)
	if err != nil {
		return controlv1.LocalProjectService{}, err
	}
	request := controlv1.RealizeLocalProjectServiceRequest{TeamId: current.team.Id, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(), Configuration: declaration.Services[name]}
	label := project.Worktree.Label.FullLabel
	if label != "" {
		request.WorktreeLabel = &label
	}
	if len(domainName) != 0 && domainName[0] != "" {
		domain, err := readyDomain(current, domainName[0])
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
	kind := "private_service"
	if publicURLID != "" {
		kind = "public_url"
	}
	if realized.Service != name || realized.WorktreeKey != request.WorktreeKey || string(realized.ServiceKind) != kind || realized.ServiceId == "" || publicURLID != "" && realized.ServiceId != publicURLID {
		return controlv1.LocalProjectService{}, failure.Wrap("realize local project service", failure.ServerResponseInvalid, errors.New("control returned another local project service"))
	}
	return realized, nil
}
