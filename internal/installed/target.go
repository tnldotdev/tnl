package installed

import (
	"crypto/x509"
	"errors"
	"net"
	"strconv"
)

func validateTarget(job *Job) error {
	if job.Kind == KindService || job.Kind == KindConnector {
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
		plan := job.TargetPlan()
		if err := plan.Normalize(); err != nil {
			return err
		}
		job.Target = plan.Target
		return nil
	}
	return ErrScope
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
