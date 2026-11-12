// package group reconciles enrolled environment publisher replicas.
package group

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type Client struct {
	control *clientcontrol.Client
	server  string
}

func NewClient(server string, transport *http.Client) (*Client, error) {
	control, err := clientcontrol.New(server, transport, "")
	return &Client{control: control, server: strings.TrimSuffix(server, "/")}, err
}

func (c *Client) Enroll(ctx context.Context, secret string, public ed25519.PublicKey) (controlv1.EnvironmentPublisher, error) {
	return c.control.RedeemEnvironmentPublisherEnrollment(ctx, secret, public)
}

func (c *Client) ServerURL() string { return c.server }

func (c *Client) PublisherRuntime(ctx context.Context, request controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	return c.control.PublisherRuntime(ctx, request)
}

func (c *Client) Lease(ctx context.Context, member controlv1.EnvironmentPublisher, private ed25519.PrivateKey) (controlv1.EnvironmentPublisherLease, error) {
	assertion, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.EnvironmentId, c.server+"/v1/environment-publishers/lease", private, time.Now())
	if err != nil {
		return controlv1.EnvironmentPublisherLease{}, err
	}
	return c.control.AcquireEnvironmentPublisherLease(ctx, controlv1.EnvironmentPublisherProof{PublisherIdentityId: member.PublisherIdentityId, EnvironmentId: member.EnvironmentId, Assertion: assertion})
}

func (c *Client) Verify(ctx context.Context, member controlv1.EnvironmentPublisher, private ed25519.PrivateKey) (controlv1.EnvironmentPublisher, error) {
	assertion, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.EnvironmentId, c.server+"/v1/environment-publishers/verify", private, time.Now())
	if err != nil {
		return controlv1.EnvironmentPublisher{}, err
	}
	return c.control.VerifyEnvironmentPublisher(ctx, controlv1.EnvironmentPublisherProof{PublisherIdentityId: member.PublisherIdentityId, EnvironmentId: member.EnvironmentId, Assertion: assertion})
}

func (c *Client) Assignments(ctx context.Context, access string) (controlv1.EnvironmentPublisherAssignments, error) {
	return c.control.GetEnvironmentPublisherAssignments(ctx, access)
}

func (c *Client) Acknowledge(ctx context.Context, access string, ack controlv1.EnvironmentPublisherAcknowledgement) error {
	return c.control.AcknowledgeEnvironmentPublisher(ctx, access, ack)
}
