package publisherjob

import (
	"context"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/targettransport"
	"github.com/tnldotdev/tnl/internal/tcptarget"
)

// PrivateTarget selects the dial address. PrivateTransport independently selects
// publisher-to-target negotiation from the approved target.tls snapshot.
func PrivateTarget(ctx context.Context, job Job) (string, func(), error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if !job.Protocol.Valid() || job.TargetTLSName != "" || len(job.TargetCAPEM) != 0 {
		return "", nil, ErrScope
	}
	if job.Protocol != config.ProtocolHTTP {
		target, err := tcptarget.Normalize(job.Target)
		if err != nil {
			return "", nil, ErrScope
		}
		return target, func() {}, nil
	}
	if !strings.Contains(job.Target, "://") {
		address, err := tcptarget.Normalize(job.Target)
		return address, func() {}, err
	}
	normalized, err := localproxy.NormalizeTarget(job.Target)
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
func PrivateTransport(job Job) (targettransport.Transport, error) {
	transport := targettransport.Transport{Protocol: job.Protocol}
	if job.Trust != nil {
		var err error
		transport.TLS, err = job.Trust.Verifier()
		if err != nil {
			return transport, err
		}
	}
	return transport, transport.Validate()
}

func PreflightPrivate(ctx context.Context, job Job) error {
	if job.Protocol == config.ProtocolHTTP && (strings.HasPrefix(job.Target, "https://") && job.Trust == nil || strings.HasPrefix(job.Target, "http://") && job.Trust != nil) {
		return ErrScope
	}
	address, close, err := PrivateTarget(ctx, job)
	if err != nil {
		return err
	}
	defer close()
	transport, err := PrivateTransport(job)
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
