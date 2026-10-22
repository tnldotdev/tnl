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

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type Options struct {
	ControlURL          string
	HTTPClient          *http.Client
	State               *clientstate.Store
	EnrollmentKey       string
	PublisherIdentityID string
	Publisher           *publisheridentity.Native
	InvocationID        string
	Target              string
	AccessMode          controlv1.VisitorAccessMode
	IP                  []string
	Limits              publisher.ApplicationLimits
	OnAllocated         func(controlv1.PublicURL) error
	Observe             func(publisher.Event) error
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
	client, err := clientcontrol.New(options.ControlURL, options.HTTPClient, "")
	if err != nil {
		return err
	}
	authority, err := clientauthority.New(options.ControlURL, options.HTTPClient, "")
	if err != nil {
		return err
	}
	native, err := publisheridentity.Resolve(ctx, options.State, client, authority, options.EnrollmentKey, options.PublisherIdentityID, options.Publisher)
	if err != nil {
		return err
	}
	if err := native.NamespaceScope(); err != nil {
		return err
	}
	if native.ControlURL() != options.ControlURL {
		return publisheridentity.ErrScope
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
	publicURL, err := native.Allocate(ctx, body)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := native.DeletePublicURL(cleanupCtx, publicURL.Id); err != nil && !errors.Is(err, clientcontrol.ErrNotFound) {
			result = errors.Join(result, fmt.Errorf("remove ad-hoc public URL: %w", err))
		}
	}()
	if publicURL.Target != target || !publicURL.Ephemeral || publicURL.LifecycleState != controlv1.Enabled ||
		publicURL.Purpose != controlv1.App || publicURL.PolicyRevision < 1 {
		return errors.New("control returned an invalid ad-hoc public URL")
	}
	if options.OnAllocated != nil {
		if err := options.OnAllocated(publicURL); err != nil {
			return err
		}
	}
	allowed := []string{}
	if publicURL.AllowedIpPrefixes != nil {
		allowed = slices.Clone(*publicURL.AllowedIpPrefixes)
	}
	membershipID := ""
	if publicURL.MembershipId != nil {
		membershipID = *publicURL.MembershipId
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	publication := publisher.Config{
		Control:        native,
		VisitorControl: client,
		ControlURL:     options.ControlURL, State: options.State,
		TeamID: publicURL.TeamId, DomainID: publicURL.DomainId, MembershipID: membershipID,
		PolicyRevision: uint64(publicURL.PolicyRevision), PublicURLScope: publicURL.PublicUrlScope,
		Purpose: controlv1.App, Hostname: publicURL.CanonicalHostname, Target: target, ServiceProtocol: controlv1.Http,
		AllowedIPPrefixes: allowed, Limits: options.Limits, Ephemeral: true, AssignedPublicURL: &publicURL,
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
