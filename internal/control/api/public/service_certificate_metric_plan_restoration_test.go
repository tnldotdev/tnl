package public

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type restoredCertificateMetricStore struct {
	managedCertificateStore
	t      *testing.T
	result controlstate.CertificateIssuance
	calls  int
}

func (s *restoredCertificateMetricStore) CreateServiceCertificateIssuance(_ context.Context, service, run, token, directory, key string, number int64, csr []byte, _ time.Time) (controlstate.CertificateIssuance, error) {
	s.t.Helper()
	if service != s.result.ServiceID || run != s.result.ServiceRunID || token != "exact-run-token" ||
		directory != "https://acme.example.test/directory" || key != "same-order" || number != 7 ||
		!bytes.Equal(csr, []byte("exact-csr")) {
		s.t.Fatal("certificate request changed its run authority or idempotent intent")
	}
	s.calls++
	result := s.result
	result.NewOrder = s.calls == 1
	if !result.NewOrder {
		result.DomainKind = ""
	}
	return result, nil
}

func TestServiceCertificateRestoredCapturedPlanMetricLabelsAndReplay(t *testing.T) {
	for _, kind := range []controlstate.DomainKind{controlstate.DomainKindManaged, controlstate.DomainKindCustom} {
		for _, shape := range []string{"exact", "wildcard"} {
			t.Run(string(kind)+"/"+shape, func(t *testing.T) {
				const namespace = "preview.example.test"
				plan := controlstate.CertificatePlan{
					CacheKey: "app." + namespace, Scope: "app." + namespace,
					Identifiers: []string{"app." + namespace}, ChallengeMethod: "dns-01",
				}
				if shape == "wildcard" {
					plan.CacheKey, plan.Scope, plan.Identifiers = namespace, namespace, []string{"*." + namespace}
				}
				metrics := observability.New("control")
				t.Cleanup(func() { _ = metrics.Shutdown(t.Context()) })
				// this store supplies committed state facts, not certificate
				// authorization. the state companion exercises real grants.
				store := &restoredCertificateMetricStore{t: t, result: controlstate.CertificateIssuance{
					ID: "issuance-one", ServiceID: "svc_" + strings.Repeat("a", 22),
					ServiceRunID: "srun_" + strings.Repeat("b", 22), ServiceRunNumber: 7,
					PublisherIdentityID: "publisher-one", DomainKind: kind,
					State: controlstate.ACMEOrderPending, CertificatePlan: plan,
				}}
				h := &handler{dependencies: Stores{ServiceCertificates: store}, config: Config{
					CertificateIssuance: true, DNSAutomation: true,
					ACMEDirectoryURL: "https://acme.example.test/directory", Metrics: metrics,
				}}
				body, err := json.Marshal(controlv1.CreateServiceCertificateIssuanceRequest{RunNumber: 7, Csr: []byte("exact-csr")})
				if err != nil {
					t.Fatal(err)
				}
				var original controlv1.ServiceCertificateIssuance
				for attempt := range 2 {
					r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
					r.Header.Set("Authorization", "Bearer exact-run-token")
					r.Header.Set("Idempotency-Key", "same-order")
					w := httptest.NewRecorder()
					h.CreateServiceCertificateIssuance(w, r, store.result.ServiceID, store.result.ServiceRunID,
						controlv1.CreateServiceCertificateIssuanceParams{})
					var got controlv1.ServiceCertificateIssuance
					if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &got) != nil {
						t.Fatalf("issuance attempt %d: HTTP %d: %s", attempt, w.Code, w.Body.String())
					}
					wantPlan := controlv1.CertificatePlan{
						CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: "dns-01",
					}
					if !reflect.DeepEqual(got.CertificatePlan, wantPlan) {
						t.Fatal("issuance response changed the captured plan", got.CertificatePlan)
					}
					if attempt == 0 {
						original = got
					} else if !reflect.DeepEqual(got, original) {
						t.Fatal("same-key replay changed the captured issuance")
					}
				}
				if store.calls != 2 {
					t.Fatalf("certificate store calls=%d, want 2", store.calls)
				}
				families, err := metrics.Gather()
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, family := range families {
					if family.GetName() != "tnl_control_certificate_orders_total" {
						continue
					}
					if len(family.Metric) != 1 {
						t.Fatalf("certificate order series=%d, want 1", len(family.Metric))
					}
					metric := family.Metric[0]
					labels := map[string]string{}
					for _, label := range metric.Label {
						labels[label.GetName()] = label.GetValue()
					}
					want := map[string]string{
						"tnl_certificate_kind": "service", "tnl_domain_kind": string(kind), "tnl_certificate_plan": shape,
					}
					if !reflect.DeepEqual(labels, want) || metric.GetCounter().GetValue() != 1 {
						t.Fatalf("captured %s plan labels/count=%v/%g, want %v/1",
							shape, labels, metric.GetCounter().GetValue(), want)
					}
					found = true
				}
				if !found {
					t.Fatal("committed certificate order metric is missing")
				}
			})
		}
	}
}
