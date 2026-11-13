package targettrust

import (
	"context"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/tcptarget"
	"github.com/tnldotdev/tnl/internal/security/rdsroots"
)

// CapturePortable accepts system roots, pinned regional RDS roots, or CA-only
// PEM. it never opens a path or fetches a URL. address is the resolved host:port;
// RDS roots require its exact database hostname, never an unrelated override.
func CapturePortable(ctx context.Context, protocol, address, ca, hostname string) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	host, err := tcptarget.Host(address)
	if err != nil {
		return Snapshot{}, ErrInvalidBundle
	}
	if hostname == "" {
		hostname = host
	}
	switch ca {
	case "", "system":
		return NewCache(nil).Capture(ctx, "", address, config.TrustSource{CA: "system", Hostname: &hostname})
	case "aws-rds":
		if protocol != "postgres" && protocol != "mysql" || hostname != host {
			return Snapshot{}, ErrInvalidBundle
		}
		bundle, err := rdsroots.BundleForHostname(host)
		if err != nil {
			return Snapshot{}, err
		}
		return CapturePEM(hostname, []byte(bundle))
	default:
		return CapturePEM(hostname, []byte(ca))
	}
}
