// package adhoc owns the scoped native Go publication lifecycle.
package adhoc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type Options struct {
	ControlURL    string
	HTTPClient    *http.Client
	State         *clientstate.Store
	EnrollmentKey string
	PublisherID   string
	Publisher     *nativeauth.Native
	InvocationID  string
	Target        string
	AccessMode    controlv1.VisitorAccessMode
	IP            []string
	Limits        publisher.ApplicationLimits
	OnAllocated   func(controlv1.PublicURL) error
	Observe       func(publisher.Event) error
}

// Run allocates one ad-hoc URL, publishes its local target, then removes the URL.
// callers retain the invocation ID across retries and worker restarts.
func Run(ctx context.Context, options Options) (result error) {
	if options.State == nil || !opaqueid.Valid(options.InvocationID, opaqueid.InvocationPrefix) {
		return errors.New("ad-hoc publisher requires client state and an invocation ID")
	}
	if err := options.Limits.Validate(); err != nil {
		return err
	}
	target, err := targetsyntax.NormalizeTarget(options.Target)
	if err != nil || target != options.Target {
		return errors.New("ad-hoc target must be an HTTP or HTTPS address with a host and port")
	}
	client, err := controlclient.New(options.ControlURL, options.HTTPClient, "")
	if err != nil {
		return err
	}
	authority, err := authorityclient.New(options.ControlURL, options.HTTPClient, "")
	if err != nil {
		return err
	}
	native, err := nativeauth.Resolve(ctx, options.State, client, authority, options.EnrollmentKey, options.PublisherID, options.Publisher)
	if err != nil {
		return err
	}
	if err := native.NamespaceScope(); err != nil {
		return err
	}
	if native.ControlURL() != options.ControlURL {
		return nativeauth.ErrScope
	}
	body := controlv1.AllocateEphemeralPublicURLRequest{InvocationId: options.InvocationID, Target: target}
	if options.AccessMode != "" {
		mode := options.AccessMode
		body.AccessMode = &mode
	}
	if options.IP != nil {
		allowed := slices.Clone(options.IP)
		body.Ip = &allowed
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
	route, err := native.Allocate(ctx, body)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := native.DeletePublicURL(cleanupCtx, route.Id); err != nil && !errors.Is(err, controlclient.ErrNotFound) {
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
		Control:        native,
		VisitorControl: client,
		ControlURL:     options.ControlURL, State: options.State,
		TeamID: route.TeamId, DomainID: route.DomainId, MembershipID: membershipID,
		PolicyRevision: uint64(route.PolicyRevision), PublicURLScope: route.PublicUrlScope,
		Purpose: controlv1.App, Hostname: route.CanonicalHostname, Target: target, ServiceProtocol: controlv1.Http,
		AllowedIPPrefixes: allowed, Limits: options.Limits, Ephemeral: true, AllocatedPublicURL: &route,
		QUICConnector: muxsession.QUICConnector{TLSConfig: tlsConfig},
		TCPConnector:  muxsession.TLSYamuxConnector{TLSConfig: tlsConfig},
		Observe:       options.Observe,
	}
	result = publisher.Run(ctx, publication)
	if ctx.Err() != nil && errors.Is(result, context.Canceled) {
		result = nil
	}
	return result
}
