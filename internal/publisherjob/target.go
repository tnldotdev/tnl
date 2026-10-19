package publisherjob

import (
	"crypto/x509"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/tcptarget"
)

func validateTarget(job *Job) error {
	if job.Kind == KindPrivateService || job.Kind == KindConnector {
		if job.TargetTLSName != "" || len(job.TargetCAPEM) != 0 {
			return ErrScope
		}
		if job.Limits.Requests != 0 || job.Limits.RateRequests != 0 || job.Limits.RatePer != 0 || job.Limits.RateBurst != 0 || job.Limits.Concurrency > 4096 {
			return ErrScope
		}
		if job.Project != nil {
			definition, found := job.Project.Config.Services[job.ProjectService]
			if job.Kind != KindPrivateService || !found || !filepath.IsAbs(job.Project.Root) || config.IsPublicService(definition) || config.Protocol(definition) != string(job.Protocol) || config.TargetType(definition) == "app" {
				return ErrScope
			}
		}
		if !job.Protocol.Valid() {
			return ErrScope
		}
		if job.Trust != nil {
			if _, err := job.Trust.Verifier(); err != nil {
				return errors.Join(ErrScope, err)
			}
		}
		if job.Kind == KindConnector {
			host, port, err := net.SplitHostPort(job.Target)
			address := net.ParseIP(host)
			n, parseErr := strconv.Atoi(port)
			if err != nil || parseErr != nil || n < 1 || n > 65535 || address == nil || !address.IsLoopback() {
				return ErrScope
			}
			return nil
		}
		var target string
		var err error
		if job.Protocol == config.ProtocolHTTP {
			if strings.HasPrefix(job.Target, "https://") && job.Trust == nil || strings.HasPrefix(job.Target, "http://") && job.Trust != nil {
				return ErrScope
			}
			target, err = config.NormalizeHTTPServiceTarget(config.Service{}, job.Target)
			if err == nil && job.Trust != nil && !strings.Contains(job.Target, "://") {
				target = "https://" + strings.TrimPrefix(target, "http://")
			}
		} else {
			target, err = tcptarget.Normalize(job.Target)
		}
		if err != nil {
			return ErrScope
		}
		job.Target = target
		return nil
	}
	if job.Kind != KindPublicURL || job.Protocol != config.ProtocolHTTP {
		return ErrScope
	}
	var err error
	job.Target, err = localproxy.NormalizeTarget(job.Target)
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
