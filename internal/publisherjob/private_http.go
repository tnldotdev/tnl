package publisherjob

import (
	"context"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	"github.com/tnldotdev/tnl/internal/targettransport"
	"github.com/tnldotdev/tnl/internal/tcptarget"
)

// PrivateTarget selects the dial address. PrivateTransport independently selects
// publisher-to-target negotiation from the approved target.tls snapshot.
func PrivateTarget(ctx context.Context, plan PrivateTargetPlan) (string, func(), error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if !plan.Protocol.Valid() {
		return "", nil, ErrScope
	}
	if plan.Protocol != config.ProtocolHTTP && plan.Protocol != config.ProtocolKubernetes {
		target, err := tcptarget.Normalize(plan.Target)
		if err != nil {
			return "", nil, ErrScope
		}
		return target, func() {}, nil
	}
	if !strings.Contains(plan.Target, "://") {
		address, err := tcptarget.Normalize(plan.Target)
		return address, func() {}, err
	}
	normalized, err := targetsyntax.NormalizeTarget(plan.Target)
	if err != nil {
		return "", nil, err
	}
	target, err := url.Parse(normalized)
	if err != nil {
		return "", nil, err
	}
	return target.Host, func() {}, nil
}

// PrivateTransport resolves only the publisher's approved target trust. visitor
// certificates and service names cannot substitute for target identity.
func PrivateTransport(plan PrivateTargetPlan) (targettransport.Transport, error) {
	return targettransport.FromTrust(plan.Protocol, plan.Trust)
}

func PreflightPrivate(ctx context.Context, plan PrivateTargetPlan) error {
	if (plan.Protocol == config.ProtocolHTTP || plan.Protocol == config.ProtocolKubernetes) && (strings.HasPrefix(plan.Target, "https://") && plan.Trust == nil || strings.HasPrefix(plan.Target, "http://") && plan.Trust != nil) {
		return ErrScope
	}
	address, close, err := PrivateTarget(ctx, plan)
	if err != nil {
		return err
	}
	defer close()
	transport, err := PrivateTransport(plan)
	if err != nil {
		return err
	}
	return transport.Preflight(ctx, address)
}

// TargetOptions builds target trust from the captured job, without reopening
// a project file after the publisher and its readiness checks have started.
func TargetOptions(job Job) (localproxy.TargetOptions, error) {
	roots, err := trustRoots(job.TargetCAPEM)
	return localproxy.TargetOptions{RootCAs: roots, ServerName: job.TargetTLSName}, err
}
