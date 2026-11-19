package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestAssignmentResponseRetainsLargeCertificateHistory(t *testing.T) {
	want := controlv1.DeploymentPublisherAssignments{CertificateStatePlans: make([]controlv1.CertificatePlan, 8193)}
	for i := range want.CertificateStatePlans {
		name := fmt.Sprintf("previous-service-%d.example", i)
		want.CertificateStatePlans[i] = controlv1.CertificatePlan{CacheKey: name, Scope: name, Identifiers: []string{name}, ChallengeMethod: controlv1.Dns01}
	}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= maxResponseBytes {
		t.Fatal("fixture does not exceed the ordinary response budget")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer publisher" {
			t.Error("assignment request lost publisher authentication")
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, get := range []func() (controlv1.DeploymentPublisherAssignments, error){
		func() (controlv1.DeploymentPublisherAssignments, error) {
			return client.GetDeploymentPublisherAssignments(t.Context(), "publisher")
		},
		func() (controlv1.DeploymentPublisherAssignments, error) {
			return client.GetDeploymentPublisherAppAssignments(t.Context(), "publisher")
		},
	} {
		got, err := get()
		if err != nil || len(got.CertificateStatePlans) != len(want.CertificateStatePlans) {
			t.Fatal("assignment response lost certificate history", len(got.CertificateStatePlans), err)
		}
	}
}
