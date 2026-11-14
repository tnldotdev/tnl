package deployment

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serverDiscoveryFunc func(context.Context) (controlv1.ControlDiscovery, error)

func (f serverDiscoveryFunc) Discovery(ctx context.Context) (controlv1.ControlDiscovery, error) {
	return f(ctx)
}

func TestPublicURLAssignmentRequiresServerDiscovery(t *testing.T) {
	failure := errors.New("discovery unavailable")
	p := AssignmentPublisher{Member: controlv1.DeploymentPublisherIdentity{DeploymentId: "deployment-one", DeploymentName: "production"}}
	a := controlv1.DeploymentPublisherServiceAssignment{
		ServiceKind: "public_url", Hostname: new("web.example.test"),
		Configuration: controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocol("http")), Target: "http://127.0.0.1:3000", PublicUrl: &controlv1.ProjectServicePublicURL{}},
	}
	if err := p.Publish(t.Context(), a, nil); !errors.Is(err, ErrAssignment) {
		t.Fatal("public URL assignment accepted missing discovery", err)
	}
	p.ServerDiscovery = serverDiscoveryFunc(func(ctx context.Context) (controlv1.ControlDiscovery, error) {
		if ctx != t.Context() {
			t.Fatal("server discovery lost its operation context")
		}
		return controlv1.ControlDiscovery{}, failure
	})
	if err := p.Publish(t.Context(), a, nil); !errors.Is(err, failure) {
		t.Fatal("public URL assignment hid discovery failure", err)
	}
}

func TestAssignmentPublisherRejectsInvalidAssignmentBeforeIdentityPreparation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*AssignmentPublisher, *controlv1.DeploymentPublisherServiceAssignment)
	}{
		{"app-owned target", func(_ *AssignmentPublisher, a *controlv1.DeploymentPublisherServiceAssignment) {
			a.Configuration.Target = "app"
		}},
		{"invalid protocol", func(_ *AssignmentPublisher, a *controlv1.DeploymentPublisherServiceAssignment) {
			a.Configuration.Protocol = new(controlv1.ServiceProtocol("invalid"))
		}},
		{"missing protocol", func(_ *AssignmentPublisher, a *controlv1.DeploymentPublisherServiceAssignment) {
			a.Configuration.Protocol = nil
		}},
		{"missing trust revision", func(_ *AssignmentPublisher, a *controlv1.DeploymentPublisherServiceAssignment) { a.TrustRevision = 0 }},
		{"negative trust revision", func(_ *AssignmentPublisher, a *controlv1.DeploymentPublisherServiceAssignment) { a.TrustRevision = -1 }},
		{"missing deployment ID", func(p *AssignmentPublisher, _ *controlv1.DeploymentPublisherServiceAssignment) {
			p.Member.DeploymentId = ""
		}},
		{"empty deployment name", func(p *AssignmentPublisher, _ *controlv1.DeploymentPublisherServiceAssignment) {
			p.Member.DeploymentName = ""
		}},
		{"local deployment", func(p *AssignmentPublisher, _ *controlv1.DeploymentPublisherServiceAssignment) {
			p.Member.DeploymentName = "local"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			assignment := controlv1.DeploymentPublisherServiceAssignment{TrustRevision: 1, Configuration: controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocol("http"))}}
			publisher := AssignmentPublisher{Member: controlv1.DeploymentPublisherIdentity{DeploymentId: "deployment-one", DeploymentName: "application"}}
			test.change(&publisher, &assignment)
			healthCalls := 0
			// no identity capabilities are supplied: validation must reject the
			// assignment before attempting native identity or target preparation.
			err := publisher.Publish(t.Context(), assignment, func(bool) { healthCalls++ })
			if !errors.Is(err, ErrAssignment) || healthCalls != 0 {
				t.Fatal("invalid assignment reached identity or health preparation", err, healthCalls)
			}
		})
	}
}

func TestAssignmentPublisherFormattingDoesNotExposeSigningKey(t *testing.T) {
	publication := AssignmentPublisher{Private: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if got := fmt.Sprintf(format, publication); got != "deployment publications" {
			t.Fatal("assignment publisher formatting exposed operation state")
		}
	}
}
