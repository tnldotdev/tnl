package deployment

import (
	"context"
	"crypto/tls"
	"encoding/json"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// installed workers use the saved-URL run owner, never URL allocation or policy
// mutation. app-owned listeners are excluded before assignments reach workers.
func (p AssignmentPublisher) publishPublicURL(ctx context.Context, assignment controlv1.DeploymentPublisherServiceAssignment, health func(bool)) error {
	s := assignment.Configuration
	if s.PublicUrl == nil || s.Protocol == nil || *s.Protocol != controlv1.ServiceProtocol("http") || s.Target == "app" || assignment.Hostname == nil || *assignment.Hostname == "" || assignment.TrustRevision < 1 || p.Member.DeploymentId == "" || p.Member.DeploymentName == "" || p.Member.DeploymentName == "local" {
		return ErrAssignment
	}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: p.Member.PublisherIdentityId, KeyId: p.Member.KeyId, TeamId: p.Member.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.SavedPublicUrl, PublicUrlId: &assignment.ServiceId}
	native, err := publisheridentity.NewNative(p.Control, p.Authority, identity, p.Private)
	if err != nil {
		return err
	}
	u, err := native.SavedPublicURL(ctx)
	if err != nil {
		return err
	}
	if u.Id != assignment.ServiceId || u.CanonicalHostname != *assignment.Hostname || u.MutationRevision != assignment.TrustRevision || u.Ephemeral || u.Target != s.Target {
		return ErrAssignment
	}
	var limits *config.Limits
	if s.PublicUrl.Limits != nil {
		data, err := json.Marshal(s.PublicUrl.Limits)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(data, &limits); err != nil {
			return err
		}
	}
	httpLimits, err := config.ResolveWorkLimits(limits, "http")
	if err != nil {
		return err
	}
	traffic, err := config.ResolveTrafficSelection(limits)
	if err != nil {
		return err
	}
	native, err = native.WithTraffic(traffic)
	if err != nil {
		return err
	}
	options := publisherproxy.TargetOptions{}
	if t := s.TargetTls; t != nil {
		declaration := targettrust.Declaration{Hostname: t.Hostname, Digest: t.Digest}
		if t.CaPem != nil {
			declaration.CAPEM = []byte(*t.CaPem)
		}
		trust, err := declaration.Snapshot()
		if err != nil {
			return err
		}
		verifier, err := trust.Verifier()
		if err != nil {
			return err
		}
		options.RootCAs, options.ServerName = verifier.RootCAs, verifier.ServerName
	}
	membership := ""
	if u.MembershipId != nil {
		membership = *u.MembershipId
	}
	if health != nil {
		defer health(false)
	}
	return publisher.Run(ctx, publisher.Config{Telemetry: p.Telemetry, Control: native, Identity: native, Audit: native, VisitorControl: native, BrowserControl: native, Shares: native, ControlURL: native.ControlURL(), State: p.State, TeamID: u.TeamId, DomainID: u.DomainId, MembershipID: membership, PublicURLScope: u.PublicUrlScope, PolicyRevision: uint64(u.PolicyRevision), Purpose: u.Purpose, Hostname: u.CanonicalHostname, Target: s.Target, ServiceProtocol: controlv1.Http, TargetOptions: options, Limits: httpLimits, TransportTLS: &tls.Config{MinVersion: tls.VersionTLS13}, Observe: func(event publisher.Event) error {
		if health != nil {
			switch event.Type {
			case publisher.EventReady:
				health(true)
			case publisher.EventProvisioning, publisher.EventDraining, publisher.EventTargetUnavailable:
				health(false)
			}
		}
		return nil
	}})
}
