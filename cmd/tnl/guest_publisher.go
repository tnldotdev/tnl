package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// the trial credential creates and deletes only its numbered demo URL; the
// signing key is required separately to start a run on that URL.
type guestSignedControl struct {
	*enrolledControl
	trial *controlclient.Client
}

func (c *guestSignedControl) GetPublicURLByHostname(ctx context.Context, teamID, hostname string) (controlv1.PublicURL, error) {
	return c.trial.GetPublicURLByHostname(ctx, teamID, hostname)
}

func (c *guestSignedControl) CreatePublicURL(ctx context.Context, body controlv1.CreatePublicURLRequest, key string) (controlv1.PublicURL, error) {
	return c.trial.CreatePublicURL(ctx, body, key)
}

func (c *guestSignedControl) DeletePublicURL(ctx context.Context, id string) error {
	return c.trial.DeletePublicURL(ctx, id)
}

func newGuestSignedControl(ctx context.Context, server string, guest clientstate.GuestSession, authenticated *clientauth.Client) (*guestSignedControl, error) {
	return newGuestSignedControlWithHTTP(ctx, server, guest, authenticated, nil)
}

func newGuestSignedControlWithHTTP(ctx context.Context, server string, guest clientstate.GuestSession, authenticated *clientauth.Client, httpClient *http.Client) (*guestSignedControl, error) {
	if authenticated == nil || authenticated.Control == nil {
		return nil, errors.New("guest demo needs an authenticated trial client")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	control, err := controlclient.New(server, httpClient, "")
	if err != nil {
		return nil, err
	}
	registered, err := control.RegisterGuestPublisherIdentity(ctx, credentials.AccessToken(guest.AccessToken), public)
	if err != nil {
		return nil, err
	}
	if !opaqueid.Valid(registered.ClientId, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(registered.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
		!opaqueid.Valid(registered.GrantId, opaqueid.PublisherGrantPrefix) ||
		registered.TeamId != guest.TeamID || registered.DomainId != guest.DomainID || registered.Namespace != guest.Namespace {
		return nil, errors.New("control returned a different guest publisher scope")
	}
	authority, err := authorityclient.New(server, httpClient, "")
	if err != nil {
		return nil, err
	}
	namespace := registered.Namespace
	return &guestSignedControl{enrolledControl: &enrolledControl{
		Client: control, authority: authority, private: private,
		identity: authorityv1.PublisherEnrollmentResult{
			ClientId: registered.ClientId, KeyId: registered.KeyId, GrantId: registered.GrantId,
			TeamId: registered.TeamId, Kind: "namespace", Namespace: &namespace,
		},
	}, trial: authenticated.Control}, nil
}
