package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/routeclient"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"tailscale.com/tailcfg"
)

type publisherServices struct {
	authenticated *clientauth.Client
	state         *clientstate.Store
	capabilities  serverv1.Capabilities
	hostname      string
	routes        *routeclient.Client
}

func authenticatePublisher(
	ctx context.Context,
	state *clientstate.Database,
	serverURL, accessToken string,
	stdin io.Reader,
	diagnostics io.Writer,
) (*clientauth.Client, error) {
	return clientauth.Authenticate(ctx, clientauth.Config{
		ServerEndpoint: serverURL,
		State:          state,
		AccessToken:    accessToken,
		Diagnostics:    diagnostics,
		LoginToken:     loginTokenPrompt(stdin, diagnostics),
	})
}

func allowCurrentIP(
	ctx context.Context,
	authenticated *clientauth.Client,
	allowedIPPrefixes []string,
	enabled bool,
) ([]string, string, error) {
	if !enabled {
		return allowedIPPrefixes, "", nil
	}
	current, err := authenticated.Server.ClientIP(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("read current IP: %w", err)
	}
	address, err := netip.ParseAddr(current.Ip)
	if err != nil || address.Zone() != "" {
		return nil, "", errors.New("server returned an invalid current IP")
	}
	currentIP := address.Unmap().String()
	allowedIPPrefixes, err = authorization.CanonicalizeIPPrefixes(append(allowedIPPrefixes, currentIP))
	if err != nil {
		return nil, "", fmt.Errorf("combine allowed IP prefixes: %w", err)
	}
	return allowedIPPrefixes, currentIP, nil
}

func preparePublisherServices(
	ctx context.Context,
	state *clientstate.Database,
	serverURL, host string,
	authenticated *clientauth.Client,
) (publisherServices, error) {
	publisherState, err := state.Server(ctx, serverURL)
	if err != nil {
		return publisherServices{}, err
	}
	capabilities := authenticated.ServerCapabilities
	if capabilities.Transport.Type != serverv1.Tailcat || capabilities.Transport.Version != serverv1.TransportCapabilitiesVersionN1 {
		return publisherServices{}, errors.New("server does not support tailcat transport version 1")
	}
	if capabilities.HostnameSuffix == "" || capabilities.MaximumSubdomainDepth != 8 {
		return publisherServices{}, errors.New("server does not support the required naming contract")
	}
	if capabilities.Acme == nil || capabilities.Acme.AcmeProfile == "" {
		return publisherServices{}, errors.New("server does not support automatic certificates")
	}
	hostnameClient, namingCapabilities, err := namingAPI(authenticated)
	if err != nil {
		return publisherServices{}, err
	}
	hostname, err := claimPublishHostname(ctx, hostnameClient, host, namingCapabilities)
	if err != nil {
		return publisherServices{}, err
	}
	routes, err := routeAPI(authenticated)
	if err != nil {
		return publisherServices{}, err
	}
	return publisherServices{
		authenticated: authenticated,
		state:         publisherState,
		capabilities:  capabilities,
		hostname:      hostname,
		routes:        routes,
	}, nil
}

func (p publisherServices) config(target string, allowedIPPrefixes []string) publisher.Config {
	return publisher.Config{
		Server:            p.routes,
		Hostname:          p.hostname,
		Target:            target,
		AllowedIPPrefixes: allowedIPPrefixes,
		State:             p.state,
		ACMEProfile:       p.capabilities.Acme.AcmeProfile,
		RelayRegion:       p.capabilities.Transport.RelayRegion,
		LoadRegions: func(ctx context.Context) (map[string]*tailcfg.DERPRegion, error) {
			relayMap, err := p.authenticated.Server.RelayMap(ctx)
			if err != nil {
				return nil, fmt.Errorf("read server relay map: %w", err)
			}
			return config.DecodeRelayRegions(relayMap)
		},
	}
}
