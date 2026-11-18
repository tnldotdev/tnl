package public

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type suppliedCertificateAPIStore struct {
	managedCertificateStore
	calls int
}

func (s *suppliedCertificateAPIStore) MarkSuppliedServiceCertificateInstalled(_ context.Context, service, run, token string, number int64, chain, previous string, _ time.Time) (controlv1.SuppliedServiceCertificateInstallation, error) {
	s.calls++
	if service != publisherCORSService || run != publisherCORSRun || number != 7 || chain != "public-supplied-chain" || previous != "" {
		return controlv1.SuppliedServiceCertificateInstallation{}, controlstate.ErrCertificateIssuanceInvalid
	}
	if token != "exact-run-token" {
		return controlv1.SuppliedServiceCertificateInstallation{}, fmt.Errorf("private-authorization-details: %w", controlstate.ErrServiceAccess)
	}
	return controlv1.SuppliedServiceCertificateInstallation{CertificateSha256: strings.Repeat("a", 64), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestSuppliedCertificateAPIUsesExplicitRunAuthorityWithoutACMEGate(t *testing.T) {
	for _, test := range []struct {
		token         string
		status, calls int
	}{
		{"", 401, 0}, {"revoked-run-token", 404, 1}, {"exact-run-token", 200, 1},
	} {
		t.Run(test.token, func(t *testing.T) {
			store := &suppliedCertificateAPIStore{}
			// supplied material must not depend on DNS-01 automation or managed
			// issuance being configured. domain and run checks remain in state.
			h := testHandler(t, Config{}, nil, nil, nil, Stores{ServiceCertificates: store})
			body, err := json.Marshal(controlv1.SuppliedServiceCertificateInstalledRequest{RunNumber: 7, CertificatePem: "public-supplied-chain"})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, publisherCORSRunPath+"/supplied-certificate-installed", bytes.NewReader(body))
			r.Header.Set("Origin", "https://arbitrary.example")
			r.Header.Set("Content-Type", "application/json")
			r.AddCookie(&http.Cookie{Name: "__Host-tnl-browser", Value: "ambient-secret"})
			if test.token != "" {
				r.Header.Set("Authorization", "Bearer "+test.token)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || store.calls != test.calls || strings.Contains(w.Body.String(), "private-authorization-details") ||
				strings.Contains(w.Body.String(), "public-supplied-chain") || strings.Contains(w.Body.String(), "run-token") {
				t.Fatal("supplied certificate API widened authority or exposed request details", w.Code, store.calls)
			}
			assertPublisherCORSResponse(t, w)
		})
	}
}
