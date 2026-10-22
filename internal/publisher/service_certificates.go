package publisher

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ServiceCertificateControl interface {
	CreateServiceCertificateIssuance(context.Context, string, string, int64, credentials.ServiceRunToken, []byte, string) (controlv1.ServiceCertificateIssuance, error)
	GetServiceCertificateIssuance(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.ServiceCertificateIssuance, error)
	MarkServiceCertificateInstalled(context.Context, string, string, int64, string, time.Time, credentials.ServiceRunToken) error
}

var errManagedIssuanceFailed = errors.New("managed certificate issuance failed")

// ServiceCertificates uses the same protected pending/current cache and DNS-01
// issuance worker as public HTTPS. every run still acknowledges its own install;
// possession of compatible cached material never grants publication authority.
type ServiceCertificates struct {
	Control             ServiceCertificateControl
	Cache               *clientstate.CertificateCache
	ServiceID           string
	RunID               string
	PublisherIdentityID string
	RunNumber           int64
	Token               credentials.ServiceRunToken
	Hostname            string
	Plan                controlv1.CertificatePlan
	Install             func(tls.Certificate) error
}

func (r ServiceCertificates) Maintain(ctx context.Context) error {
	if r.Control == nil || r.Cache == nil || r.Install == nil || r.RunNumber < 1 || !opaqueid.Valid(r.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || r.Plan.ChallengeMethod != controlv1.Dns01 || !certificateidentity.Covers(r.Plan.Identifiers, r.Hostname) {
		return ErrEndpoint
	}
	var installed clientstate.Material
	terminalRetried := false
	for {
		material, err := r.advance(ctx, installed.Certificate.Leaf == nil)
		if err != nil {
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			if errors.Is(err, errManagedIssuanceFailed) && !terminalRetried {
				terminalRetried = true
				lock, lockErr := r.Cache.Lock(ctx)
				if lockErr != nil {
					return lockErr
				}
				_, replaceErr := r.Cache.NewPending(ctx, r.Hostname)
				_ = lock.Close()
				if replaceErr != nil {
					if !managedCertificateRetryable(replaceErr) {
						return replaceErr
					}
				}
			} else if !managedCertificateRetryable(err) {
				return err
			}
			delay := time.Second
			if installed.Certificate.Leaf != nil {
				if !installed.Certificate.Leaf.NotAfter.After(time.Now()) {
					return errCertificateExpired
				}
				delay = min(time.Minute, time.Until(installed.Certificate.Leaf.NotAfter))
			}
			if err = waitCertificateRetry(ctx, delay); err != nil {
				return err
			}
			continue
		}
		if err = r.Install(material.Certificate); err != nil {
			return err
		}
		installed = material
		terminalRetried = false
		if err = waitCertificateRetry(ctx, max(time.Until(material.RenewAt), time.Second)); err != nil {
			return err
		}
	}
}

func managedCertificateRetryable(err error) bool {
	if errors.Is(err, clientcontrol.ErrUnavailable) || errors.Is(err, clientcontrol.ErrRateLimited) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	if reason, ok := failure.ReasonOf(err); ok {
		definition, exists := failure.DefinitionFor(reason)
		return exists && definition.Retry == failure.RetryLater
	}
	var network net.Error
	return errors.As(err, &network)
}

func (r ServiceCertificates) advance(ctx context.Context, initial bool) (_ clientstate.Material, result error) {
	ctx, finish := observability.PublisherOperation(ctx, "certificate")
	defer func() { finish(result) }()
	lock, err := r.Cache.Lock(ctx)
	if err != nil {
		return clientstate.Material{}, err
	}
	defer lock.Close()
	current, found, err := r.Cache.Current(ctx, r.Hostname)
	if err != nil && !errors.Is(err, clientstate.ErrCertificateExpired) {
		return current, err
	}
	if err == nil && found && (initial || time.Now().Before(current.RenewAt)) {
		err = r.Control.MarkServiceCertificateInstalled(ctx, r.ServiceID, r.RunID, r.RunNumber, current.IssuanceID, current.Certificate.Leaf.NotAfter, r.Token)
		return current, err
	}
	staged, stagedFound, err := r.Cache.Staged(ctx, r.Hostname)
	if err != nil && !errors.Is(err, clientstate.ErrCertificateExpired) {
		return current, err
	}
	if err == nil && stagedFound {
		return r.promote(ctx, staged)
	}
	if errors.Is(err, clientstate.ErrCertificateExpired) {
		if _, err = r.Cache.NewPending(ctx, r.Hostname); err != nil {
			return current, err
		}
	}
	pending, err := r.Cache.Pending(ctx, r.Hostname)
	if err != nil {
		return current, err
	}
	digest := sha256.Sum256(pending.CSRDER)
	issuance, err := r.Control.CreateServiceCertificateIssuance(ctx, r.ServiceID, r.RunID, r.RunNumber, r.Token, pending.CSRDER, hex.EncodeToString(digest[:]))
	if err != nil {
		return current, err
	}
	for {
		if issuance.PublisherIdentityId != r.PublisherIdentityID || !opaqueid.Valid(issuance.ServiceId, opaqueid.ServicePrefix) || !opaqueid.Valid(issuance.ServiceRunId, opaqueid.ServiceRunPrefix) || issuance.RunNumber < 1 || !certificateidentity.SamePlan(issuance.CertificatePlan, r.Plan) {
			return current, ErrEndpoint
		}
		if issuance.CertificatePem != nil {
			if issuance.NotBefore == nil || issuance.NotAfter == nil || !issuance.NotAfter.After(time.Now()) {
				return current, ErrEndpoint
			}
			block, _ := pem.Decode([]byte(*issuance.CertificatePem))
			if block == nil || block.Type != "CERTIFICATE" {
				return current, ErrEndpoint
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil || !leaf.NotBefore.Equal(*issuance.NotBefore) || !leaf.NotAfter.Equal(*issuance.NotAfter) {
				return current, ErrEndpoint
			}
			staged, err := r.Cache.Stage(ctx, r.Hostname, pending, []byte(*issuance.CertificatePem), certificateRenewAt(leaf.NotBefore, leaf.NotAfter), issuance.Id)
			if err != nil {
				return current, err
			}
			return r.promote(ctx, staged)
		}
		if issuance.State == controlv1.CertificateIssuanceStateFailed || issuance.State == controlv1.CertificateIssuanceStateCanceled {
			return current, errManagedIssuanceFailed
		}
		delay := time.Second
		if issuance.RetryAt != nil {
			delay = max(100*time.Millisecond, min(5*time.Second, time.Until(*issuance.RetryAt)))
		}
		if err := waitCertificateRetry(ctx, delay); err != nil {
			return current, err
		}
		issuance, err = r.Control.GetServiceCertificateIssuance(ctx, r.ServiceID, r.RunID, issuance.Id, r.Token)
		if err != nil {
			return current, err
		}
	}
}

func (r ServiceCertificates) promote(ctx context.Context, staged clientstate.Material) (clientstate.Material, error) {
	if err := r.Control.MarkServiceCertificateInstalled(ctx, r.ServiceID, r.RunID, r.RunNumber, staged.IssuanceID, staged.Certificate.Leaf.NotAfter, r.Token); err != nil {
		return staged, err
	}
	if err := r.Cache.Promote(ctx, r.Hostname, staged.IssuanceID); err != nil {
		return staged, err
	}
	return staged, nil
}
