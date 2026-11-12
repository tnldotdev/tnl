package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestEnvironmentPublisherEnrollmentCarriesExplicitIntentKey(t *testing.T) {
	for _, key := range []string{"", "customer/42/enrollment/one"} {
		name := "human-omits-key"
		if key != "" {
			name = "machine-retains-key"
		}
		t.Run(name, func(t *testing.T) {
			const environment = "env_AAAAAAAAAAAAAAAAAAAAAA"
			var observed []string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1/projects/accounts/environments/"+environment+"/publisher-enrollments" {
					t.Error("enrollment changed its exact environment selection")
				}
				observed = append(observed, r.Header.Get("Idempotency-Key"))
				if key == "" && len(r.Header.Values("Idempotency-Key")) != 0 {
					t.Error("empty human key was sent as a present invalid header")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(controlv1.EnvironmentPublisherEnrollment{Ref: controlv1.EnvironmentReference{Server: "https://control.example.test", ProjectKey: "accounts", EnvironmentId: environment}, EnrollmentKey: "test-enrollment", ExpiresAt: time.Now().Add(time.Minute), MaxMembers: 1})
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "test-access")
			if err != nil {
				t.Fatal(err)
			}
			body := controlv1.CreateEnvironmentPublisherEnrollmentRequest{TeamId: "team_AAAAAAAAAAAAAAAAAAAAAA", ExpectedRevision: 1, ConfigurationHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Services: []string{"api"}, MaxMembers: 1, ExpiresIn: 60}
			for range 2 {
				if _, err := client.CreateEnvironmentPublisherEnrollment(t.Context(), "accounts", environment, key, body); err != nil {
					t.Fatal(err)
				}
			}
			if len(observed) != 2 || observed[0] != key || observed[1] != key {
				t.Fatal("enrollment adapter changed intent across retries", observed)
			}
		})
	}
}
