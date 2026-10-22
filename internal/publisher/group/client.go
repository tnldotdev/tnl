// package grouppublisher reconciles one signed publisher-group replica.
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

func (c *Client) Enroll(ctx context.Context, secret string, public ed25519.PublicKey) (controlv1.PublisherGroupMember, error) {
	return c.control.RedeemPublisherGroupEnrollment(ctx, secret, public)
}

func (c *Client) ServerURL() string { return c.server }

func (c *Client) PublisherRuntime(ctx context.Context, request controlv1.PublisherRuntimeRequest) (controlv1.PublisherRuntimeResponse, error) {
	return c.control.PublisherRuntime(ctx, request)
}

func (c *Client) Lease(ctx context.Context, member controlv1.PublisherGroupMember, private ed25519.PrivateKey) (controlv1.PublisherGroupLease, error) {
	assertion, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.GroupId, c.server+"/v1/publisher-groups/lease", private, time.Now())
	if err != nil {
		return controlv1.PublisherGroupLease{}, err
	}
	return c.control.AcquirePublisherGroupLease(ctx, controlv1.PublisherGroupLeaseRequest{PublisherIdentityId: member.PublisherIdentityId, GroupId: member.GroupId, Assertion: assertion})
}

func (c *Client) Verify(ctx context.Context, member controlv1.PublisherGroupMember, private ed25519.PrivateKey) (controlv1.PublisherGroupVerification, error) {
	assertion, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.GroupId, c.server+"/v1/publisher-groups/verify", private, time.Now())
	if err != nil {
		return controlv1.PublisherGroupVerification{}, err
	}
	return c.control.VerifyPublisherGroupIdentity(ctx, controlv1.PublisherGroupLeaseRequest{PublisherIdentityId: member.PublisherIdentityId, GroupId: member.GroupId, Assertion: assertion})
}

func (c *Client) Assignments(ctx context.Context, access string) (controlv1.PublisherGroupAssignments, error) {
	return c.control.GetPublisherGroupAssignments(ctx, access)
}

func (c *Client) Acknowledge(ctx context.Context, access string, ack controlv1.PublisherGroupAcknowledgement) error {
	return c.control.AcknowledgePublisherGroupConfiguration(ctx, access, ack)
}
