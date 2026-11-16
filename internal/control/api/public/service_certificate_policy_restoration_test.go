package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceCertificateRestoredDNSAutomationGateBeforeStore(t *testing.T) {
	store := &restoredCertificateMetricStore{t: t}
	h := &handler{dependencies: Stores{ServiceCertificates: store},
		config: Config{CertificateIssuance: true, DNSAutomation: false}}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"run_number":"7","csr":"ZXhhY3QtY3Ny"}`))
	r.Header.Set("Authorization", "Bearer exact-run-token")
	r.Header.Set("Idempotency-Key", "same-order")
	w := httptest.NewRecorder()
	h.CreateServiceCertificateIssuance(w, r, "service", "run", controlv1.CreateServiceCertificateIssuanceParams{})
	var problem controlv1.Problem
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &problem) != nil || problem.Code != controlv1.Unavailable || store.calls != 0 {
		t.Fatal("unsupported DNS-01 issuance plan reached the certificate store", w.Code, store.calls)
	}
}
