package group

import (
	"context"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type Manager interface {
	GetProjectConfiguration(context.Context, string, string) (controlv1.AppliedProjectConfiguration, error)
	CreatePublisherGroup(context.Context, string, string, controlv1.CreatePublisherGroupRequest) (controlv1.PublisherGroupConnection, error)
	RemovePublisherGroup(context.Context, string, string, string, int64) error
}

func Create(ctx context.Context, client Manager, team, project, name, template string) (controlv1.PublisherGroupConnection, error) {
	if !naming.ValidServiceName(name) || name == "local" || !naming.ValidServiceName(template) {
		return controlv1.PublisherGroupConnection{}, ErrAssignment
	}
	current, err := client.GetProjectConfiguration(ctx, team, project)
	if err != nil {
		return controlv1.PublisherGroupConnection{}, err
	}
	result, err := client.CreatePublisherGroup(ctx, project, name, controlv1.CreatePublisherGroupRequest{TeamId: team, From: template, ExpectedRevision: current.Revision})
	if err != nil {
		return result, err
	}
	if result.TeamId != team || result.ProjectKey != project || result.GroupName != name || !opaqueid.Valid(result.GroupId, "pgrp_") || result.SourceFingerprint != current.SourceFingerprint {
		return controlv1.PublisherGroupConnection{}, ErrAssignment
	}
	return result, nil
}

func Remove(ctx context.Context, client Manager, team, project, name string) error {
	current, err := client.GetProjectConfiguration(ctx, team, project)
	if err != nil {
		return err
	}
	return client.RemovePublisherGroup(ctx, team, project, name, current.Revision)
}
