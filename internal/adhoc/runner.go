// package adhoc owns the publication lifecycle shared by local SDKs.
package adhoc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type Options struct {
	ControlURL   string
	HTTPClient   *http.Client
	State        *clientstate.Store
	Credential   credentials.EphemeralCredential
	InvocationID string
	Target       string
	AllowIP      []string
	AllowAllIPs  bool
	Limits       publisher.ApplicationLimits
	OnAllocated  func(controlv1.PublicURL) error
	Observe      func(publisher.Event) error
}

// Run allocates one ad-hoc URL, publishes its local target, then removes the URL.
// callers retain the invocation ID across retries and worker restarts.
func Run(ctx context.Context, options Options) (result error) {
	if options.State == nil || !opaqueid.Valid(options.InvocationID, opaqueid.InvocationPrefix) {
		return errors.New("ad-hoc publisher requires client state and an invocation ID")
	}
	if _, _, _, err := credentials.ParseEphemeralCredential(options.Credential); err != nil {
		return err
	}
	if err := options.Limits.Validate(); err != nil {
		return err
	}
	target, err := localproxy.NormalizeTarget(options.Target)
	parsed, parseErr := url.Parse(target)
	if err != nil || target != options.Target || parseErr != nil ||
		parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" {
		return errors.New("ad-hoc publisher requires a canonical loopback target")
	}
	client, err := controlclient.New(options.ControlURL, options.HTTPClient, "")
	if err != nil {
		return err
	}
	body := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: options.InvocationID, Target: target}
	if options.AllowAllIPs {
		body.AllowAllIps = &options.AllowAllIPs
	} else if len(options.AllowIP) != 0 {
		allowed := slices.Clone(options.AllowIP)
		body.AllowIp = &allowed
	}
	if options.Limits.Requests != 0 || options.Limits.RateRequests != 0 || options.Limits.Concurrency != 0 {
		limits := &controlv1.PublisherApplicationLimits{}
		if options.Limits.Requests != 0 {
			limits.Requests = &options.Limits.Requests
		}
		if options.Limits.Concurrency != 0 {
			limits.Concurrency = &options.Limits.Concurrency
		}
		if options.Limits.RateRequests != 0 {
			limits.Rate = &struct {
				Per      string `json:"per"`
				Requests int    `json:"requests"`
			}{Per: options.Limits.RatePer.String(), Requests: options.Limits.RateRequests}
		}
		body.Limits = limits
	}
	route, err := client.AllocateEphemeralPublicURL(ctx, options.Credential, body)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.DeleteEphemeralPublicURL(cleanupCtx, options.Credential, route.Id); err != nil && !errors.Is(err, controlclient.ErrNotFound) {
			result = errors.Join(result, fmt.Errorf("remove ad-hoc public URL: %w", err))
		}
	}()
	if route.Target != target || !route.Ephemeral || route.LifecycleState != controlv1.Enabled ||
		route.Purpose != controlv1.App || route.PolicyRevision < 1 {
		return errors.New("control returned an invalid ad-hoc public URL")
	}
	if options.OnAllocated != nil {
		if err := options.OnAllocated(route); err != nil {
			return err
		}
	}
	allowed := []string{}
	if route.AllowedIpPrefixes != nil {
		allowed = slices.Clone(*route.AllowedIpPrefixes)
	}
	membershipID := ""
	if route.MembershipId != nil {
		membershipID = *route.MembershipId
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	publication := publisher.Config{
		Control:    &scopedControl{Client: client, route: route, credential: options.Credential},
		ControlURL: options.ControlURL, State: options.State,
		TeamID: route.TeamId, DomainID: route.DomainId, MembershipID: membershipID,
		PolicyRevision: uint64(route.PolicyRevision), PublicURLScope: route.PublicUrlScope,
		Purpose: controlv1.App, Hostname: route.CanonicalHostname, Target: target,
		AllowedIPPrefixes: allowed, Limits: options.Limits, Ephemeral: true, AllocatedPublicURL: &route,
		QUICConnector: muxsession.QUICConnector{TLSConfig: tlsConfig},
		TCPConnector:  muxsession.TLSYamuxConnector{TLSConfig: tlsConfig},
		Observe:       options.Observe,
	}
	return publisher.Run(ctx, publication)
}
