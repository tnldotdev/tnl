package group

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestAssignmentPublisherRejectsInvalidAssignmentBeforeIdentityPreparation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*AssignmentPublisher, *controlv1.PublisherGroupServiceAssignment)
	}{
		{"missing service kind", func(_ *AssignmentPublisher, a *controlv1.PublisherGroupServiceAssignment) { a.ServiceKind = "" }},
		{"public URL", func(_ *AssignmentPublisher, a *controlv1.PublisherGroupServiceAssignment) {
			a.ServiceKind = "public_url"
		}},
		{"missing protocol", func(_ *AssignmentPublisher, a *controlv1.PublisherGroupServiceAssignment) {
			a.Configuration.Protocol = nil
		}},
		{"missing trust revision", func(_ *AssignmentPublisher, a *controlv1.PublisherGroupServiceAssignment) { a.TrustRevision = 0 }},
		{"negative trust revision", func(_ *AssignmentPublisher, a *controlv1.PublisherGroupServiceAssignment) { a.TrustRevision = -1 }},
		{"missing deployment ID", func(p *AssignmentPublisher, _ *controlv1.PublisherGroupServiceAssignment) { p.Member.GroupId = "" }},
		{"empty deployment name", func(p *AssignmentPublisher, _ *controlv1.PublisherGroupServiceAssignment) { p.Member.GroupName = "" }},
		{"local deployment", func(p *AssignmentPublisher, _ *controlv1.PublisherGroupServiceAssignment) {
			p.Member.GroupName = "local"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			assignment := controlv1.PublisherGroupServiceAssignment{ServiceKind: "service", TrustRevision: 1, Configuration: controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocol("http"))}}
			publisher := AssignmentPublisher{Member: controlv1.PublisherGroupMember{GroupId: "deployment-one", GroupName: "application"}}
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
		if got := fmt.Sprintf(format, publication); got != "publisher group publications" {
			t.Fatal("assignment publisher formatting exposed operation state")
		}
	}
}
