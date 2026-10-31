package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) GetProjectService(ctx context.Context, project, service string, params controlv1.GetProjectServiceParams) (controlv1.Service, error) {
	return requestWithAccess[controlv1.Service](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetProjectService(ctx, project, service, &params, editors...)
	})
}

func (c *Client) ApplyProjectConfiguration(ctx context.Context, project string, body controlv1.ApplyProjectConfigurationRequest) (controlv1.AppliedProjectConfiguration, error) {
	return requestWithAccess[controlv1.AppliedProjectConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ApplyProjectConfiguration(ctx, project, body, editors...)
	})
}

func (c *Client) RenamePublisherNamespace(ctx context.Context, project, group string, body controlv1.RenamePublisherNamespaceRequest) (controlv1.AppliedProjectConfiguration, error) {
	return requestWithAccess[controlv1.AppliedProjectConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenamePublisherNamespace(ctx, project, group, body, editors...)
	})
}

func (c *Client) RenamePublisherGroup(ctx context.Context, project, group string, body controlv1.RenamePublisherGroupRequest) (controlv1.AppliedProjectConfiguration, error) {
	return requestWithAccess[controlv1.AppliedProjectConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenamePublisherGroup(ctx, project, group, body, editors...)
	})
}

func (c *Client) GetProjectConfiguration(ctx context.Context, team, project string) (controlv1.AppliedProjectConfiguration, error) {
	return requestWithAccess[controlv1.AppliedProjectConfiguration](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetProjectConfiguration(ctx, project, &controlv1.GetProjectConfigurationParams{TeamId: team}, editors...)
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

func (c *Client) CreatePublisherGroupEnrollment(ctx context.Context, project, group string, body controlv1.CreatePublisherGroupEnrollmentRequest) (controlv1.PublisherGroupEnrollment, error) {
	return requestWithAccess[controlv1.PublisherGroupEnrollment](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublisherGroupEnrollment(ctx, project, group, body, editors...)
	})
}

func (c *Client) RedeemPublisherGroupEnrollment(ctx context.Context, key string, public ed25519.PublicKey) (controlv1.PublisherGroupMember, error) {
	return request[controlv1.PublisherGroupMember](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemPublisherGroupEnrollment(ctx, controlv1.RedeemPublisherGroupEnrollmentRequest{EnrollmentKey: key, PublicKey: base64.RawURLEncoding.EncodeToString(public)}, editors...)
	})
}

func (c *Client) AcquirePublisherGroupLease(ctx context.Context, body controlv1.PublisherGroupLeaseRequest) (controlv1.PublisherGroupLease, error) {
	return request[controlv1.PublisherGroupLease](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcquirePublisherGroupLease(ctx, body, editors...)
	})
}

func (c *Client) VerifyPublisherGroupIdentity(ctx context.Context, body controlv1.PublisherGroupLeaseRequest) (controlv1.PublisherGroupVerification, error) {
	return request[controlv1.PublisherGroupVerification](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.VerifyPublisherGroupIdentity(ctx, body, editors...)
	})
}

func (c *Client) GetPublisherGroupAssignments(ctx context.Context, token string) (controlv1.PublisherGroupAssignments, error) {
	return request[controlv1.PublisherGroupAssignments](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetPublisherGroupAssignments(ctx, editors...)
	})
}

func (c *Client) AcknowledgePublisherGroupConfiguration(ctx context.Context, token string, body controlv1.PublisherGroupAcknowledgement) error {
	_, err := request[struct{}](ctx, c, token, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcknowledgePublisherGroupConfiguration(ctx, body, editors...)
	})
	return err
}

func (c *Client) RevokePublisherGroupMember(ctx context.Context, team, project, group, publisher string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokePublisherGroupMember(ctx, project, group, publisher, &controlv1.RevokePublisherGroupMemberParams{TeamId: team}, editors...)
	})
	return err
}
