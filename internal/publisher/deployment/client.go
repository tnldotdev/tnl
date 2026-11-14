// package grouppublisher reconciles one signed deployment-publisher replica.
package deployment

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

func (c *Client) Enroll(ctx context.Context, secret string, public ed25519.PublicKey) (controlv1.DeploymentPublisherIdentity, error) {
	return c.control.RedeemDeploymentPublisherEnrollment(ctx, secret, public)
}

func (c *Client) ServerURL() string { return c.server }

func (c *Client) PublisherRuntime(ctx context.Context, request controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	return c.control.PublisherRuntime(ctx, request)
}

func (c *Client) Lease(ctx context.Context, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) (controlv1.DeploymentPublisherLease, error) {
	assertion, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.DeploymentId, c.server+"/v1/publisher/deployments/lease", private, time.Now())
	if err != nil {
		return controlv1.DeploymentPublisherLease{}, err
	}
	return c.control.AcquireDeploymentPublisherLease(ctx, controlv1.DeploymentPublisherLeaseRequest{PublisherIdentityId: member.PublisherIdentityId, DeploymentId: member.DeploymentId, Assertion: assertion})
}

func (c *Client) Verify(ctx context.Context, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) (controlv1.DeploymentPublisherVerification, error) {
	assertion, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.DeploymentId, c.server+"/v1/publisher/deployments/verify", private, time.Now())
	if err != nil {
		return controlv1.DeploymentPublisherVerification{}, err
	}
	return c.control.VerifyDeploymentIdentity(ctx, controlv1.DeploymentPublisherLeaseRequest{PublisherIdentityId: member.PublisherIdentityId, DeploymentId: member.DeploymentId, Assertion: assertion})
}

func (c *Client) Assignments(ctx context.Context, access string) (controlv1.DeploymentPublisherAssignments, error) {
	return c.control.GetDeploymentPublisherAssignments(ctx, access)
}

func (c *Client) Acknowledge(ctx context.Context, access string, ack controlv1.DeploymentPublisherAcknowledgement) error {
	return c.control.AcknowledgeDeploymentPublisherConfiguration(ctx, access, ack)
}
