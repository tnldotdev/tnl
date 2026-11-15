package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type certificateRecoveryControl struct {
	*lifecycleControl
	store     *clientstate.Store
	create    func([]byte, string) (controlv1.ServiceCertificateIssuance, error)
	get       func(context.Context, string) (controlv1.ServiceCertificateIssuance, error)
	installed func(string, time.Time) error
}

func (c *certificateRecoveryControl) GetServiceCertificateIssuance(ctx context.Context, service, run, issuance string, token credentials.ServiceRunToken) (controlv1.ServiceCertificateIssuance, error) {
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || token.String() != c.setup.RunToken {
		return controlv1.ServiceCertificateIssuance{}, ErrPrivateStream
	}
	if c.get != nil {
		return c.get(ctx, issuance)
	}
	return c.lifecycleControl.GetServiceCertificateIssuance(ctx, service, run, issuance, token)
}

func (c *certificateRecoveryControl) CreateServiceCertificateIssuance(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken, csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || number != c.prep.RunNumber || token.String() != c.setup.RunToken {
		return controlv1.ServiceCertificateIssuance{}, ErrPrivateStream
	}
	if c.create != nil {
		return c.create(csr, key)
	}
	issued, err := c.lifecycleControl.CreateServiceCertificateIssuance(ctx, service, run, number, token, csr, key)
	issued.Id = "test-issuance-" + key
	return issued, err
}

func (c *certificateRecoveryControl) MarkServiceCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, notAfter time.Time, token credentials.ServiceRunToken) error {
	if service != c.prep.ServiceId || run != c.prep.ServiceRunId || number != c.prep.RunNumber || token.String() != c.setup.RunToken {
		return ErrPrivateStream
	}
	if c.installed != nil {
		return c.installed(issuance, notAfter)
	}
	return c.lifecycleControl.MarkServiceCertificateInstalled(ctx, service, run, number, issuance, notAfter, token)
}

func certificateRecoveryFixture(t *testing.T) (Certificates, *certificateRecoveryControl, *Prepared) {
	t.Helper()
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := newManagedPrepared(control.prep, approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := cfg.State.CertificatesForPublisher(control.prep.TeamId, cfg.PublisherIdentityID, *control.prep.CertificatePlan)
	if err != nil {
		t.Fatal(err)
	}
	recovery := &certificateRecoveryControl{lifecycleControl: control, store: cfg.State}
	return Certificates{Control: recovery, Cache: cache, ServiceID: control.prep.ServiceId,
		RunID: control.prep.ServiceRunId, RunNumber: control.prep.RunNumber,
		PublisherIdentityID: cfg.PublisherIdentityID, Token: credentials.ServiceRunToken(control.setup.RunToken),
		Hostname: control.prep.Hostname, Plan: *control.prep.CertificatePlan, Install: prepared.installManagedCertificate}, recovery, prepared
}

func TestServiceCertificateRecoversCreateAndInstallResponseLoss(t *testing.T) {
	for _, phase := range []string{"create", "installed"} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/committed=%t", phase, committed), func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				var issued controlv1.ServiceCertificateIssuance
				var firstCSR []byte
				var firstKey string
				lost, acknowledged := false, false
				control.create = func(csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
					if firstCSR == nil {
						firstCSR, firstKey = bytes.Clone(csr), key
					} else if !bytes.Equal(firstCSR, csr) || firstKey != key {
						t.Error("response-loss recovery changed the CSR or idempotency key")
					}
					if phase == "create" && !lost && !committed {
						lost = true
						return controlv1.ServiceCertificateIssuance{}, clientcontrol.ErrUnavailable
					}
					if issued.Id == "" {
						var err error
						issued, err = control.lifecycleControl.CreateServiceCertificateIssuance(t.Context(),
							certificates.ServiceID, certificates.RunID, certificates.RunNumber, certificates.Token, csr, key)
						if err != nil {
							return issued, err
						}
					}
					if phase == "create" && !lost {
						lost = true
						return controlv1.ServiceCertificateIssuance{}, clientcontrol.ErrUnavailable
					}
					return issued, nil
				}
				control.installed = func(id string, notAfter time.Time) error {
					staged, found, err := certificates.Cache.Staged(t.Context(), certificates.Hostname)
					if err != nil || !found || staged.IssuanceID != id || !staged.Certificate.Leaf.NotAfter.Equal(notAfter) {
						t.Error("installation acknowledgment preceded durable matching material", found, err)
					}
					if _, err := prepared.currentCertificate(); err == nil {
						t.Error("unacknowledged initial certificate reached the serving owner")
					}
					if phase == "installed" && !lost {
						lost, acknowledged = true, committed
						return clientcontrol.ErrUnavailable
					}
					acknowledged = true
					return nil
				}
				if _, err := certificates.advance(t.Context(), true); !errors.Is(err, clientcontrol.ErrUnavailable) || !lost {
					t.Fatal("response-loss boundary was not reached", err)
				}
				if _, found, err := certificates.Cache.Current(t.Context(), certificates.Hostname); err != nil || found {
					t.Fatal("lost response promoted unacknowledged material", found, err)
				}
				// a new cache handle recovers durable pending or staged state,
				// rather than depending on an in-memory issuance attempt.
				cache, err := control.store.CertificatesForPublisher(control.prep.TeamId, certificates.PublisherIdentityID, certificates.Plan)
				if err != nil {
					t.Fatal(err)
				}
				certificates.Cache = cache
				material, err := certificates.advance(t.Context(), true)
				if err != nil || !acknowledged || material.IssuanceID != issued.Id {
					t.Fatal("the exact certificate transaction did not recover", acknowledged, err)
				}
				if err := certificates.Install(material.Certificate); err != nil {
					t.Fatal(err)
				}
				current, err := prepared.currentCertificate()
				if err != nil || !bytes.Equal(current.Certificate[0], material.Certificate.Certificate[0]) {
					t.Fatal("acknowledged certificate was not available to its serving owner", err)
				}
			})
		}
	}
}

func TestServiceCertificateLostRenewalAcknowledgmentPreservesCurrent(t *testing.T) {
	for _, failure := range []error{clientcontrol.ErrUnavailable, clientcontrol.ErrStatusConflict, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				initial, err := certificates.advance(t.Context(), true)
				if err != nil {
					t.Fatal(err)
				}
				if err := certificates.Install(initial.Certificate); err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Until(initial.RenewAt))
				control.installed = func(string, time.Time) error { return failure }
				if _, err := certificates.advance(t.Context(), false); !errors.Is(err, failure) {
					t.Fatal("renewal lost the installation failure", err)
				}
				current, found, err := certificates.Cache.Current(t.Context(), certificates.Hostname)
				if err != nil || !found || current.IssuanceID != initial.IssuanceID {
					t.Fatal("unacknowledged renewal displaced durable current material", found, err)
				}
				serving, err := prepared.currentCertificate()
				if err != nil || !bytes.Equal(serving.Certificate[0], initial.Certificate.Certificate[0]) {
					t.Fatal("unacknowledged renewal displaced the serving certificate", err)
				}
				staged, found, err := certificates.Cache.Staged(t.Context(), certificates.Hostname)
				if err != nil || !found || staged.IssuanceID == initial.IssuanceID {
					t.Fatal("renewal lost its recoverable staged material", found, err)
				}
				if bytes.Equal(staged.Certificate.Leaf.RawSubjectPublicKeyInfo, initial.Certificate.Leaf.RawSubjectPublicKeyInfo) {
					t.Fatal("renewal reused the current application key")
				}
				control.create = func([]byte, string) (controlv1.ServiceCertificateIssuance, error) {
					return controlv1.ServiceCertificateIssuance{}, errors.New("staged renewal requested another issuance")
				}
				control.installed = nil
				recovered, err := certificates.advance(t.Context(), false)
				if err != nil || recovered.IssuanceID != staged.IssuanceID {
					t.Fatal("staged renewal did not recover", err)
				}
				if err := certificates.Install(recovered.Certificate); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestServiceCertificateCachedMaterialAcknowledgesEachRun(t *testing.T) {
	certificates, control, _ := certificateRecoveryFixture(t)
	initial, err := certificates.advance(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	control.create = func([]byte, string) (controlv1.ServiceCertificateIssuance, error) {
		return controlv1.ServiceCertificateIssuance{}, errors.New("compatible cached material requested another issuance")
	}
	acknowledgments := 0
	control.installed = func(id string, notAfter time.Time) error {
		if id != initial.IssuanceID || !notAfter.Equal(initial.Certificate.Leaf.NotAfter) {
			t.Error("new run acknowledged different cached material")
		}
		acknowledgments++
		return nil
	}
	for range 2 {
		id, err := opaqueid.New(opaqueid.ServiceRunPrefix)
		if err != nil {
			t.Fatal(err)
		}
		control.prep.ServiceRunId, certificates.RunID = id, id
		control.prep.RunNumber++
		certificates.RunNumber = control.prep.RunNumber
		material, err := certificates.advance(t.Context(), true)
		if err != nil || material.IssuanceID != initial.IssuanceID {
			t.Fatal("new run failed to acknowledge compatible cached material", err)
		}
	}
	if acknowledgments != 2 {
		t.Fatal("cached certificate skipped a run's installation acknowledgment", acknowledgments)
	}
}
