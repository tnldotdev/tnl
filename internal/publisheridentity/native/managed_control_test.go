package native

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var _ privatepublisher.RunControl = (*ManagedControl)(nil)
var _ ManagedCertificateControl = (*Native)(nil)
var _ managedHTTPControl = (*Native)(nil)

type managedBoundaryControl struct {
	NativeControl
	managedControl
	token credentials.ManagedRunToken
	calls int
}

func (c *managedBoundaryControl) HeartbeatPrivateServiceRunHealth(_ context.Context, _, _ string, token credentials.ManagedRunToken, _ controlv1.PrivateServiceRunHeartbeat) (controlv1.PrivateServiceRunState, error) {
	c.token, c.calls = token, c.calls+1
	return controlv1.PrivateServiceRunState{}, nil
}

func (c *managedBoundaryControl) AuthorizeManagedHTTPVisitor(_ context.Context, _, _ string, token credentials.ManagedRunToken, _ controlv1.ManagedHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	c.token, c.calls = token, c.calls+1
	return controlv1.ServiceClientCertificateDecision{}, nil
}

func TestNativeManagedViewPreservesLegacySignaturesAndExactScope(t *testing.T) {
	n, _ := privateScopeFixture(t)
	c := &managedBoundaryControl{}
	n.NativeControl = c
	token, _, err := credentials.NewManagedRunToken()
	if err != nil {
		t.Fatal(err)
	}
	service := n.identity.privateServiceID
	if _, err := n.ManagedRunControl().HeartbeatPrivateServiceRunHealth(t.Context(), service, "run", token, controlv1.PrivateServiceRunHeartbeat{}); err != nil || c.token != token || c.calls != 1 {
		t.Fatal("typed managed lifecycle changed its run token", err)
	}
	// the public alias still accepts its original token type, with conversion
	// confined to this compatibility boundary rather than the typed lifecycle.
	legacy := credentials.PublishRunToken(token)
	if _, err := n.HeartbeatPrivateServiceRunHealth(t.Context(), service, "run", legacy, controlv1.PrivateServiceRunHeartbeat{}); err != nil || c.token != token || c.calls != 2 {
		t.Fatal("legacy public method no longer reaches managed control", err)
	}
	if _, err := n.AuthorizeManagedHTTPVisitor(t.Context(), service, "run", legacy, controlv1.ManagedHTTPVisitorRequest{}); err != nil || c.token != token || c.calls != 3 {
		t.Fatal("legacy public visitor method changed", err)
	}
	if _, err := n.ManagedRunControl().AuthorizeManagedHTTPVisitor(t.Context(), "another-service", "run", token, controlv1.ManagedHTTPVisitorRequest{}); !errors.Is(err, ErrScope) || c.calls != 3 {
		t.Fatal("typed managed view escaped its private-service grant", err)
	}
	if _, err := n.AuthorizeManagedHTTPVisitor(t.Context(), "another-service", "run", legacy, controlv1.ManagedHTTPVisitorRequest{}); !errors.Is(err, ErrScope) || c.calls != 3 {
		t.Fatal("legacy managed view escaped its private-service grant", err)
	}
}
