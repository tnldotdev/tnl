package controlapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type certificateOrderStore struct {
	Store
	issuance controlstate.CertificateIssuance
}

func (s *certificateOrderStore) PublishRunAuthentication(_ context.Context, id string, number uint64, token credentials.PublishRunToken) (controlstate.PublishRunAuthentication, error) {
	return controlstate.PublishRunAuthentication{PublishRunID: id, PublishRunNumber: number, PublishRunToken: token}, nil
}

func (s *certificateOrderStore) CreateCertificateIssuance(context.Context, controlstate.CreateCertificateIssuanceRequest, time.Time) (controlstate.CertificateIssuance, error) {
	result := s.issuance
	s.issuance.NewOrder = false
	return result, nil
}

func TestCertificateOrderMetricExcludesIdempotentRetries(t *testing.T) {
	for _, kind := range []controlstate.DomainKind{controlstate.DomainKindManaged, controlstate.DomainKindClaimed} {
		for _, plan := range []string{"exact", "wildcard"} {
			t.Run(string(kind)+"/"+plan, func(t *testing.T) {
				identifiers := []string{"api.member.example.test"}
				if plan == "wildcard" {
					identifiers = []string{"member.example.test", "*.member.example.test"}
				}
				metrics := observability.New("control")
				store := &certificateOrderStore{issuance: controlstate.CertificateIssuance{
					NewOrder: true, DomainKind: kind, CertificatePlan: controlstate.CertificatePlan{Identifiers: identifiers},
				}}
				h := &handler{store: store, certificates: store, config: Config{CertificateIssuance: true, Metrics: metrics}}
				for range 2 {
					request := httptest.NewRequest(http.MethodPost, "/v1/publish-runs/run/certificate-issuances", strings.NewReader(`{"publish_run_number":1,"csr":"Y3Ny"}`))
					request.Header.Set("Authorization", "Bearer run-token")
					request.Header.Set("Idempotency-Key", "same-order")
					response := httptest.NewRecorder()
					h.CreateCertificateIssuance(response, request, "run", controlv1.CreateCertificateIssuanceParams{})
					if response.Code != http.StatusCreated {
						t.Fatalf("issuance status = %d: %s", response.Code, response.Body.String())
					}
				}
				response := httptest.NewRecorder()
				metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				want := `tnl_control_public_url_certificate_orders_total{domain_kind="` + string(kind) + `",plan="` + plan + `"} 1`
				if !strings.Contains(response.Body.String(), want) {
					t.Fatalf("committed order counted incorrectly: missing %s", want)
				}
			})
		}
	}
}
