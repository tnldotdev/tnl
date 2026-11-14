package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicationAuthority struct {
	client, grant, key string
	private            ed25519.PrivateKey
	calls              int
}

func (a *publicationAuthority) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if client != a.client || grant != a.grant || key != a.key || !bytes.Equal(private, a.private) {
		return "", ErrScope
	}
	a.calls++
	return "access", nil
}

type namedPublicationControl struct {
	*privateScopeControl
	team, project, deployment, name string
	resolveErr                      error
}

func (c *namedPublicationControl) DeploymentPublication(_ context.Context, access, team, project, deployment, name string) (controlv1.Service, error) {
	if access != "access" || team != c.team || project != c.project || deployment != c.deployment || name != c.name {
		return controlv1.Service{}, ErrScope
	}
	return c.service, c.resolveErr
}

func namedPublicationFixture(t *testing.T) (*namedPublicationControl, *publicationAuthority, controlv1.DeploymentCredential) {
	t.Helper()
	exact, control := privateScopeFixture(t)
	control.service.Protocol = controlv1.ServiceProtocolHTTP
	authority := &publicationAuthority{client: exact.identity.clientID, grant: exact.identity.grantID, key: exact.identity.keyID, private: exact.private}
	approval := controlv1.DeploymentCredential{ClientId: authority.client, GrantId: authority.grant, KeyId: authority.key, TeamId: "team", ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour)}
	return &namedPublicationControl{privateScopeControl: control, team: approval.TeamId, project: approval.ProjectKey, deployment: "production", name: "web"}, authority, approval
}

func TestPrepareDeploymentKeepsActualGrantAndKeyWithExactServiceSelection(t *testing.T) {
	control, authority, approval := namedPublicationFixture(t)
	native, service, err := PrepareDeployment(t.Context(), control, authority, approval, authority.private, control.deployment, control.name)
	if err != nil {
		t.Fatal(err)
	}
	if native.identity.kind != "deployment_credential" || native.identity.serviceID != "" ||
		native.selectedServiceID != service.Id || native.identity.grantID != approval.GrantId ||
		native.identity.clientID != approval.ClientId || native.identity.keyID != approval.KeyId ||
		!bytes.Equal(native.private, authority.private) || authority.calls != 1 {
		t.Fatal("named selection changed credential facts or manufactured an exact grant")
	}
	*service = controlv1.Service{}
	approved, err := native.SavedService(t.Context())
	if err != nil || approved.Id != control.service.Id {
		t.Fatal("caller mutation changed the selected service", err)
	}
	if _, err := native.PrepareServiceRun(t.Context(), approved.Id, "attempt", "access", ServiceDeclaration(approved)); err != nil {
		t.Fatal(err)
	}
	if len(control.declarations) != 1 || authority.calls != 3 {
		t.Fatal("service preparation did not use the original signed credential")
	}
	other, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	reads := control.reads
	if _, err := native.GetPublisherService(t.Context(), other, "access"); !errors.Is(err, ErrScope) || control.reads != reads {
		t.Fatal("bound worker read another service", err)
	}
	if _, _, err := native.ForService(t.Context(), other); !errors.Is(err, ErrScope) {
		t.Fatal("bound worker changed its service", err)
	}
	fork, err := native.Fork()
	if err != nil || fork.identity.kind != "deployment_credential" || fork.selectedServiceID != native.selectedServiceID || fork.identity.grantID != native.identity.grantID {
		t.Fatal("fork changed registered credential or selected service", err)
	}
	if err := native.NamespaceScope(); !errors.Is(err, ErrScope) {
		t.Fatal("registered publication manufactured namespace permission", err)
	}
}

func TestPrepareDeploymentRejectsUnapprovedOrInvalidServiceWithoutFallback(t *testing.T) {
	for _, boundary := range []string{"permission", "team", "protocol", "disabled", "id", "expired-service", "expired-grant", "missing-name"} {
		t.Run(boundary, func(t *testing.T) {
			control, authority, approval := namedPublicationFixture(t)
			name := control.name
			switch boundary {
			case "permission":
				control.resolveErr = ErrScope
			case "team":
				control.service.TeamId = "other"
			case "protocol":
				control.service.Protocol = controlv1.Postgres
			case "disabled":
				control.service.Enabled = false
			case "id":
				control.service.Id = "invalid"
			case "expired-service":
				control.service.ExpiresAt = new(time.Now().Add(-time.Second))
			case "expired-grant":
				approval.ExpiresAt = time.Now().Add(-time.Second)
			case "missing-name":
				name = ""
			}
			native, service, err := PrepareDeployment(t.Context(), control, authority, approval, authority.private, control.deployment, name)
			if err == nil || native != nil || service != nil || control.reads != 0 || len(control.declarations) != 0 {
				t.Fatal("invalid selection returned a worker or fell back to another publication")
			}
		})
	}
}
