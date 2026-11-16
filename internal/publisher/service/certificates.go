package service

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

	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type CertificateControl interface {
	CreateServiceCertificateIssuance(context.Context, string, string, int64, credentials.ServiceRunToken, []byte, string) (controlv1.ServiceCertificateIssuance, error)
	GetServiceCertificateIssuance(context.Context, string, string, string, credentials.ServiceRunToken) (controlv1.ServiceCertificateIssuance, error)
	MarkServiceCertificateInstalled(context.Context, string, string, int64, string, time.Time, credentials.ServiceRunToken) error
}

var errManagedIssuanceFailed = errors.New("managed certificate issuance failed")
var errCertificateExpired = errors.New("publisher: service certificate expired")

// Certificates uses the same protected pending/current cache and DNS-01
// issuance worker as public HTTPS. every run still acknowledges its own install;
// possession of compatible cached material never grants publication authority.
type Certificates struct {
	Control             CertificateControl
	Cache               *clientstate.CertificateCache
	ServiceID           string
	RunID               string
	PublisherIdentityID string
	RunNumber           int64
	Token               credentials.ServiceRunToken
	Hostname            string
	Plan                controlv1.CertificatePlan
	Install             func(tls.Certificate) error
	installed           chan<- struct{}
}

func (r Certificates) Maintain(ctx context.Context) error {
	if r.Control == nil || r.Cache == nil || r.Install == nil || r.RunNumber < 1 || !opaqueid.Valid(r.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || r.Plan.ChallengeMethod != controlv1.Dns01 || !certificateidentity.Covers(r.Plan.Identifiers, r.Hostname) {
		return servicestream.ErrEndpoint
	}
	var installed clientstate.Material
	terminalRetried := false
	for {
		retriedTerminal := false
		material, err := func() (clientstate.Material, error) {
			attempt := ctx
			stop := func() {}
			if installed.Certificate.Leaf != nil {
				// renewal cannot outlive the certificate currently serving visitors,
				// including cache-lock waits, pending orders, and control requests.
				attempt, stop = context.WithDeadlineCause(ctx, installed.Certificate.Leaf.NotAfter, errCertificateExpired)
			}
			defer stop()
			material, err := r.advance(attempt, installed.Certificate.Leaf == nil)
			if attempt.Err() == nil && errors.Is(err, errManagedIssuanceFailed) && !terminalRetried {
				terminalRetried, retriedTerminal = true, true
				lock, lockErr := r.Cache.Lock(attempt)
				if lockErr != nil {
					err = errors.Join(err, lockErr)
					retriedTerminal = managedCertificateRetryable(lockErr)
				} else {
					_, replaceErr := r.Cache.NewPending(attempt, r.Hostname)
					replaceErr = errors.Join(replaceErr, lock.Close())
					if replaceErr != nil {
						err = errors.Join(err, replaceErr)
						retriedTerminal = managedCertificateRetryable(replaceErr)
					}
				}
			}
			if attempt.Err() != nil {
				return material, errors.Join(context.Cause(attempt), serviceWorkerError(err, attempt.Err()))
			}
			return material, err
		}()
		if err != nil {
			if ctx.Err() != nil {
				return errors.Join(context.Cause(ctx), serviceWorkerError(err, ctx.Err()))
			}
			if errors.Is(err, errCertificateExpired) || !retriedTerminal && !managedCertificateRetryable(err) {
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
		// wake the run owner only after serving installation succeeds. coalesced
		// notifications request a readiness recheck, not a grant of authority.
		select {
		case r.installed <- struct{}{}:
		default:
		}
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

func (r Certificates) advance(ctx context.Context, initial bool) (_ clientstate.Material, result error) {
	ctx, finish := observability.PublisherOperation(ctx, "certificate")
	defer func() { finish(result) }()
	// atomic current snapshots can be acknowledged by a new run while another
	// worker holds the separate issuance lock for renewal.
	current, found, err := r.Cache.Current(ctx, r.Hostname)
	if err != nil && !errors.Is(err, clientstate.ErrCertificateExpired) {
		return current, err
	}
	if err == nil && found && (initial || time.Now().Before(current.RenewAt)) {
		err = r.Control.MarkServiceCertificateInstalled(ctx, r.ServiceID, r.RunID, r.RunNumber, current.IssuanceID, current.Certificate.Leaf.NotAfter, r.Token)
		return current, err
	}
	lock, err := r.Cache.Lock(ctx)
	if err != nil {
		return clientstate.Material{}, err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	current, found, err = r.Cache.Current(ctx, r.Hostname)
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
	selectedIssuance := issuance.Id
	for {
		if err := context.Cause(ctx); err != nil {
			return current, err
		}
		if err := r.validateIssuance(issuance, selectedIssuance); err != nil {
			return current, err
		}
		if issuance.CertificatePem != nil {
			if issuance.NotBefore == nil || issuance.NotAfter == nil || !issuance.NotAfter.After(time.Now()) {
				return current, servicestream.ErrEndpoint
			}
			block, _ := pem.Decode([]byte(*issuance.CertificatePem))
			if block == nil || block.Type != "CERTIFICATE" {
				return current, servicestream.ErrEndpoint
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil || !leaf.NotBefore.Equal(*issuance.NotBefore) || !leaf.NotAfter.Equal(*issuance.NotAfter) {
				return current, servicestream.ErrEndpoint
			}
			staged, err := r.Cache.Stage(ctx, r.Hostname, pending, []byte(*issuance.CertificatePem), certificateidentity.RenewAt(leaf.NotBefore, leaf.NotAfter), issuance.Id)
			if err != nil {
				return current, err
			}
			return r.promote(ctx, staged)
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

// a shared order may originate in another run with the same publisher and plan.
// polling must retain that selected order, and only installable states can carry
// material. reject inconsistent responses before staging or acknowledging them.
func (r Certificates) validateIssuance(issuance controlv1.ServiceCertificateIssuance, selected string) error {
	if selected == "" || issuance.Id != selected || issuance.PublisherIdentityId != r.PublisherIdentityID ||
		!opaqueid.Valid(issuance.ServiceId, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(issuance.ServiceRunId, opaqueid.ServiceRunPrefix) || issuance.RunNumber < 1 ||
		!certificateidentity.SamePlan(issuance.CertificatePlan, r.Plan) || !issuance.State.Valid() {
		return servicestream.ErrEndpoint
	}
	installable := issuance.State == controlv1.CertificateIssuanceStateWaitingForInstall ||
		issuance.State == controlv1.CertificateIssuanceStateInstalled
	if (issuance.CertificatePem != nil) != installable {
		return servicestream.ErrEndpoint
	}
	if issuance.State == controlv1.CertificateIssuanceStateFailed || issuance.State == controlv1.CertificateIssuanceStateCanceled {
		return errManagedIssuanceFailed
	}
	return nil
}

func (r Certificates) promote(ctx context.Context, staged clientstate.Material) (clientstate.Material, error) {
	if err := r.Control.MarkServiceCertificateInstalled(ctx, r.ServiceID, r.RunID, r.RunNumber, staged.IssuanceID, staged.Certificate.Leaf.NotAfter, r.Token); err != nil {
		return staged, err
	}
	if err := r.Cache.Promote(ctx, r.Hostname, staged.IssuanceID); err != nil {
		return staged, err
	}
	return staged, nil
}

func waitCertificateRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return context.Cause(ctx)
	}
}
