package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"maps"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) GetProjectService(ctx context.Context, project, service string, params controlv1.GetProjectServiceParams) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetProjectService(ctx, project, service, &params, editors...)
	})
}

func (c *Client) ApplyProjectConfiguration(ctx context.Context, project string, body controlv1.ApplyProjectConfigurationRequest) (controlv1.AppliedProjectConfiguration, error) {
	// digests are resolved output; send only the desired trust material.
	body.Configuration.Services = maps.Clone(body.Configuration.Services)
	for name, service := range body.Configuration.Services {
		if service.TargetTls != nil {
			trust := *service.TargetTls
			trust.Digest = ""
			service.TargetTls = &trust
			body.Configuration.Services[name] = service
		}
	}
	return requestWithAccess[controlv1.AppliedProjectConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ApplyProjectConfiguration(ctx, project, body, editors...)
	})
}

func (c *Client) RetireProject(ctx context.Context, project string, body controlv1.RetireProjectJSONRequestBody) (controlv1.AppliedProjectConfiguration, error) {
	return requestWithAccess[controlv1.AppliedProjectConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RetireProject(ctx, project, body, editors...)
	})
}

func (c *Client) ListProjects(ctx context.Context, params controlv1.ListProjectsParams) (controlv1.ProjectPage, error) {
	return requestWithAccess[controlv1.ProjectPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListProjects(ctx, &params, editors...)
	})
}

func (c *Client) GetProjectStatus(ctx context.Context, project string, params controlv1.GetProjectStatusParams) (controlv1.ProjectStatus, error) {
	return requestWithAccess[controlv1.ProjectStatus](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetProjectStatus(ctx, project, &params, editors...)
	})
}

func (c *Client) ResolveProjectSource(ctx context.Context, source controlv1.GitProjectSource) (controlv1.ProjectSourceIdentity, error) {
	return requestWithAccess[controlv1.ProjectSourceIdentity](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ResolveProjectSource(ctx, source, editors...)
	})
}

func (c *Client) ListPreviews(ctx context.Context, params controlv1.ListPreviewsParams) (controlv1.PreviewPage, error) {
	return requestWithAccess[controlv1.PreviewPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListPreviews(ctx, &params, editors...)
	})
}

func (c *Client) RenameDeploymentNamespace(ctx context.Context, project, deployment string, body controlv1.RenameDeploymentNamespaceRequest) (controlv1.AppliedProjectConfiguration, error) {
	return requestWithAccess[controlv1.AppliedProjectConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenameDeploymentNamespace(ctx, project, deployment, body, editors...)
	})
}

func (c *Client) RenameDeployment(ctx context.Context, project, deployment string, body controlv1.RenameDeploymentRequest) (controlv1.AppliedProjectConfiguration, error) {
	return requestWithAccess[controlv1.AppliedProjectConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenameDeployment(ctx, project, deployment, body, editors...)
	})
}

func (c *Client) GetProjectConfiguration(ctx context.Context, team, project, deployment string) (controlv1.AppliedProjectConfiguration, error) {
	return requestWithAccess[controlv1.AppliedProjectConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetProjectConfiguration(ctx, project, &controlv1.GetProjectConfigurationParams{TeamId: team, Deployment: deployment}, editors...)
	})
}

func (c *Client) RealizeLocalProjectService(ctx context.Context, project, service string, body controlv1.RealizeLocalProjectServiceRequest) (controlv1.LocalProjectService, error) {
	return requestWithAccess[controlv1.LocalProjectService](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RealizeLocalProjectService(ctx, project, service, body, editors...)
	})
}

func (c *Client) GetLocalProjectService(ctx context.Context, project, service string, params controlv1.GetLocalProjectServiceParams) (controlv1.LocalProjectService, error) {
	return requestWithAccess[controlv1.LocalProjectService](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetLocalProjectService(ctx, project, service, &params, editors...)
	})
}

func (c *Client) GetProjectPublicMetadata(ctx context.Context, team, project string) (controlv1.ProjectPublicMetadata, error) {
	return requestWithAccess[controlv1.ProjectPublicMetadata](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetProjectPublicMetadata(ctx, project, &controlv1.GetProjectPublicMetadataParams{TeamId: team}, editors...)
	})
}

func (c *Client) RedeemDeploymentPublisherEnrollment(ctx context.Context, key string, public ed25519.PublicKey) (controlv1.DeploymentPublisherIdentity, error) {
	return request[controlv1.DeploymentPublisherIdentity](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemDeploymentPublisherEnrollment(ctx, controlv1.RedeemDeploymentPublisherEnrollmentRequest{EnrollmentKey: key, PublicKey: base64.RawURLEncoding.EncodeToString(public)}, editors...)
	})
}

func (c *Client) AcquireDeploymentPublisherLease(ctx context.Context, body controlv1.DeploymentPublisherLeaseRequest) (controlv1.DeploymentPublisherLease, error) {
	return request[controlv1.DeploymentPublisherLease](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcquireDeploymentPublisherLease(ctx, body, editors...)
	})
}

func (c *Client) VerifyDeploymentIdentity(ctx context.Context, body controlv1.DeploymentPublisherLeaseRequest) (controlv1.DeploymentPublisherVerification, error) {
	return request[controlv1.DeploymentPublisherVerification](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.VerifyDeploymentIdentity(ctx, body, editors...)
	})
}

func (c *Client) GetDeploymentPublisherAssignments(ctx context.Context, token string) (controlv1.DeploymentPublisherAssignments, error) {
	return request[controlv1.DeploymentPublisherAssignments](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetDeploymentPublisherAssignments(ctx, editors...)
	})
}

func (c *Client) AcknowledgeDeploymentPublisherConfiguration(ctx context.Context, token string, body controlv1.DeploymentPublisherAcknowledgement) error {
	_, err := request[struct{}](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcknowledgeDeploymentPublisherConfiguration(ctx, body, editors...)
	})
	return err
}
