package service

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/state/certificatestore"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type certificateStoreFunc func(string, string, controlv1.CertificatePlan) (*certificatestore.CertificateCache, error)

func (f certificateStoreFunc) CertificatesForPublisher(team, publisher string, plan controlv1.CertificatePlan) (*certificatestore.CertificateCache, error) {
	return f(team, publisher, plan)
}

func TestServiceCertificateStoreDoesNotRequireNativeState(t *testing.T) {
	config, control := lifecycleFixture(t)
	config.State = nil
	called := false
	selectedErr := errors.New("host certificate storage unavailable")
	config.CertificateStore = certificateStoreFunc(func(team, publisher string, plan controlv1.CertificatePlan) (*certificatestore.CertificateCache, error) {
		called = true
		if team != control.prep.TeamId || publisher != config.PublisherIdentityID || !certificateidentity.SamePlan(plan, *control.prep.CertificatePlan) {
			t.Fatal("certificate storage selected outside the approved ownership or plan")
		}
		return nil, selectedErr
	})
	approved, err := control.GetPublisherService(t.Context(), config.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := newManagedPrepared(control.prep, approved, config)
	if err != nil {
		t.Fatal(err)
	}
	maintain, closeRun, err := configureServiceRun(context.Background(), config, prepared, control.setup, control, nil, nil)
	if !called || !errors.Is(err, selectedErr) || maintain != nil || closeRun != nil {
		t.Fatal("nil native state bypassed the explicit host storage boundary", err)
	}
}
