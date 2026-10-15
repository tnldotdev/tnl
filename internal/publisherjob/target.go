package publisherjob

import (
	"crypto/x509"
	"net"
	"strings"

	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/tcptarget"
)

func validateTarget(job *Job) error {
	var err error
	if job.Protocol == "http" {
		if job.TargetTLS || job.TargetTLSName != "" {
			return ErrScope
		}
		job.Target, err = localproxy.NormalizeTarget(job.Target)
		if len(job.TargetCAPEM) > 0 && !strings.HasPrefix(job.Target, "https://") {
			return ErrScope
		}
	} else {
		job.Target, err = tcptarget.Normalize(job.Target)
		if !job.TargetTLS && (job.TargetTLSName != "" || len(job.TargetCAPEM) > 0) {
			return ErrScope
		}
		if job.TargetTLSName != "" && net.ParseIP(job.TargetTLSName) == nil {
			if _, e := naming.CanonicalizeHostname(job.TargetTLSName); e != nil {
				return ErrScope
			}
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
	if len(pem) > 128<<10 {
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
