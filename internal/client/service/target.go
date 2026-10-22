package publisherjob

import (
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
)

func validateTarget(job *Job) error {
	if job.Kind == KindPrivateService || job.Kind == KindConnector {
		if job.TargetTLSName != "" || len(job.TargetCAPEM) != 0 {
			return ErrScope
		}
		if job.Limits.Requests != 0 || job.Limits.RateRequests != 0 || job.Limits.RatePer != 0 || job.Limits.RateBurst != 0 || job.Limits.Concurrency > 4096 {
			return ErrScope
		}
		if !job.Protocol.Valid() {
			return ErrScope
		}
		if job.Kind == KindConnector {
			if job.Project != nil {
				return ErrScope
			}
			if job.Trust != nil {
				if _, err := job.Trust.Verifier(); err != nil {
					return errors.Join(ErrScope, err)
				}
			}
			host, port, err := net.SplitHostPort(job.Target)
			address := net.ParseIP(host)
			n, parseErr := strconv.Atoi(port)
			if err != nil || parseErr != nil || n < 1 || n > 65535 || address == nil || !address.IsLoopback() {
				return ErrScope
			}
			return nil
		}
		plan := job.PrivateTargetPlan()
		if err := plan.Normalize(); err != nil {
			return err
		}
		job.Target = plan.Target
		return nil
	}
	if job.Kind != KindPublicURL || job.Protocol != config.ProtocolHTTP {
		return ErrScope
	}
	var err error
	job.Target, err = targetsyntax.NormalizeTarget(job.Target)
	if (len(job.TargetCAPEM) > 0 || job.TargetTLSName != "") && !strings.HasPrefix(job.Target, "https://") {
		return ErrScope
	}
	if job.TargetTLSName != "" && net.ParseIP(job.TargetTLSName) == nil {
		if _, e := naming.CanonicalizeHostname(job.TargetTLSName); e != nil {
			return ErrScope
		}
	}
	if err != nil {
		return ErrScope
	}
	if _, err := trustRoots(job.TargetCAPEM); err != nil {
		return err
	}
	_, err = trustRoots(job.ServerCAPEM)
	return err
}

func trustRoots(pem []byte) (*x509.CertPool, error) {
	if len(pem) == 0 {
		return nil, nil
	}
	if len(pem) > 1<<20 {
		return nil, ErrScope
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, ErrScope
	}
	return roots, nil
}

// ValidateTrust checks a copied CA snapshot before one-use enrollment starts.
func ValidateTrust(pem []byte) error {
	_, err := trustRoots(pem)
	return err
}
