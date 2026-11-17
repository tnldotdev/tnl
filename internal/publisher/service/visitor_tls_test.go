package service

import (
	"crypto/tls"
	"errors"
	"reflect"
	"testing"
)

func TestServiceVisitorTLSUsesTheCapturedRequirement(t *testing.T) {
	for _, required := range []bool{false, true} {
		name := "default"
		if required {
			name = "post-quantum"
		}
		t.Run(name, func(t *testing.T) {
			cfg, control := lifecycleFixture(t)
			approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
			if err != nil {
				t.Fatal(err)
			}
			preparation := control.prep
			approved.RequirePostQuantum, preparation.RequirePostQuantum = required, required
			prepared, err := newManagedPrepared(preparation, approved, cfg)
			if err != nil {
				t.Fatal(err)
			}
			visitorTLS := prepared.visitorTLS
			if visitorTLS == nil || visitorTLS.GetCertificate == nil {
				t.Fatal("service lost its managed visitor certificate")
			}
			if required {
				if visitorTLS.MinVersion != tls.VersionTLS13 || !reflect.DeepEqual(visitorTLS.CurvePreferences, []tls.CurveID{tls.X25519MLKEM768}) {
					t.Fatal("service did not enforce the approved visitor TLS requirement")
				}
			} else if visitorTLS.MinVersion != tls.VersionTLS12 || len(visitorTLS.CurvePreferences) != 0 {
				t.Fatal("default service unexpectedly narrowed visitor TLS")
			}
			prepared.Preparation.RequirePostQuantum = !required
			if prepared.visitorTLS != visitorTLS || prepared.managedTargetTLS != nil {
				t.Fatal("wire mutation changed captured visitor TLS or enabled target TLS")
			}
		})
	}
}

func TestServiceVisitorTLSRejectsAChangedPreparation(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []bool{false, true} {
		preparation := control.prep
		approved.RequirePostQuantum, preparation.RequirePostQuantum = required, !required
		if _, err := newManagedPrepared(preparation, approved, cfg); !errors.Is(err, ErrPrivateStream) {
			t.Fatal("service accepted a different visitor TLS requirement", err)
		}
	}
}
