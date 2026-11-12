package authority

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/httpjson"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func (c *Client) PrepareEnvironmentVisitor(ctx context.Context, project, environment string, body authorityv1.EnvironmentVisitorPrepareRequest) (authorityv1.EnvironmentVisitorPreparation, error) {
	payload, err := requestPayload(ctx, c, "", func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.PrepareEnvironmentVisitor(ctx, project, environment, body, editors...)
	})
	if err != nil {
		return authorityv1.EnvironmentVisitorPreparation{}, err
	}
	var result authorityv1.EnvironmentVisitorPreparation
	if err := httpjson.DecodeNonNullObject(payload, &result, "environment", "applied_definition_revision", "mutation_revision", "services", "session"); err != nil {
		return result, failure.Wrap("decode environment visitor preparation", failure.ServerResponseInvalid, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return authorityv1.EnvironmentVisitorPreparation{}, failure.Wrap("decode environment visitor preparation", failure.ServerResponseInvalid, err)
	}
	if _, err := decodeEnvironmentVisitorSession(fields["session"]); err != nil {
		return authorityv1.EnvironmentVisitorPreparation{}, err
	}
	return result, nil
}

func (c *Client) AttachEnvironmentVisitorAssertion(ctx context.Context, id, credential string, body authorityv1.EnvironmentVisitorAssertion) (authorityv1.EnvironmentVisitorSession, error) {
	payload, err := requestPayload(ctx, c, credential, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AttachEnvironmentVisitorAssertion(ctx, id, body, editors...)
	})
	if err != nil {
		return authorityv1.EnvironmentVisitorSession{}, err
	}
	return decodeEnvironmentVisitorSession(payload)
}

func (c *Client) RenewEnvironmentVisitorSession(ctx context.Context, id, credential string, body authorityv1.EnvironmentVisitorRenewal) (authorityv1.EnvironmentVisitorSession, error) {
	payload, err := requestPayload(ctx, c, credential, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RenewEnvironmentVisitorSession(ctx, id, body, editors...)
	})
	if err != nil {
		return authorityv1.EnvironmentVisitorSession{}, err
	}
	return decodeEnvironmentVisitorSession(payload)
}

func decodeEnvironmentVisitorSession(payload []byte) (result authorityv1.EnvironmentVisitorSession, err error) {
	err = httpjson.DecodeNonNullObject(payload, &result, "id", "credential", "subject", "service_ids", "renewal_sequence", "lease_expires_at", "identity_expires_at", "renew_after")
	if err != nil {
		return authorityv1.EnvironmentVisitorSession{}, failure.Wrap("decode environment visitor session", failure.ServerResponseInvalid, err)
	}
	return result, nil
}

func (c *Client) RevokeEnvironmentVisitorSession(ctx context.Context, id, credential string) error {
	_, err := requestWithToken[struct{}](ctx, c, credential, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeEnvironmentVisitorSession(ctx, id, editors...)
	})
	return err
}
