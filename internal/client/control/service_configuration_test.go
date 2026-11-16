package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceConfigurationClientRequiresStrongDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, status := range []int{200, 204} {
		for _, tag := range []string{strconv.Quote(digest), "", digest, "W/" + strconv.Quote(digest), strconv.Quote(strings.ToUpper(digest)), strconv.Quote(digest + "a")} {
			t.Run(strconv.Itoa(status)+"/"+tag, func(t *testing.T) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/v1/services/svc_selected/configuration" || r.Header.Get("Authorization") != "Bearer person-token" {
						t.Error("read changed exact service selection or management credential")
					}
					w.Header().Set("ETag", tag)
					w.Header().Set("Cache-Control", "no-store")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					if status == 200 {
						_ = json.NewEncoder(w).Encode(controlv1.ProjectServiceConfiguration{Target: "private-listener.internal:3000"})
					}
				}))
				defer server.Close()
				client, err := New(server.URL, server.Client(), "person-token")
				if err != nil {
					t.Fatal(err)
				}
				declaration, got, err := client.GetServiceConfiguration(t.Context(), "svc_selected")
				if tag != strconv.Quote(digest) {
					if err == nil || declaration != nil || got != "" {
						t.Fatal("malformed ETag returned usable configuration")
					}
					return
				}
				if err != nil || got != digest || (declaration == nil) != (status == 204) {
					t.Fatal("read lost its declaration or opaque digest", err)
				}
				if declaration != nil && declaration.Target != "private-listener.internal:3000" {
					t.Fatal("client replaced the private target")
				}
			})
		}
	}
}

func TestServiceConfigurationClientSendsExactCondition(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body controlv1.UpdateServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || r.Method != http.MethodPut || r.URL.Path != "/v1/services/svc_selected" ||
			r.Header.Get("Authorization") != "Bearer person-token" || body.Configuration == nil || body.Configuration.Target != "private-listener.internal:3000" ||
			body.ExpectedConfigurationDigest == nil || *body.ExpectedConfigurationDigest != digest || body.ExpectedTrustRevision != 7 {
			t.Error("replacement changed the declaration or its independent conditions", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlv1.Service{Id: "svc_selected"})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "person-token")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ConfigureService(t.Context(), "svc_selected", controlv1.UpdateServiceRequest{
		Protocol: controlv1.ServiceProtocolHTTP, ExpectedTrustRevision: 7, ExpectedConfigurationDigest: &digest,
		Configuration: &controlv1.ProjectServiceConfiguration{Target: "private-listener.internal:3000"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestServiceConfigurationClientSendsExplicitUnconditionalChoice(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body controlv1.UpdateServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Configuration == nil ||
			body.Configuration.Target != "private-listener.internal:3000" || body.ExpectedConfigurationDigest != nil ||
			body.UnconditionalConfiguration == nil || !*body.UnconditionalConfiguration || body.ExpectedTrustRevision != 7 {
			t.Error("unconditional replacement changed its explicit choice or bypassed trust revision", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlv1.Service{Id: "svc_selected"})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "person-token")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ConfigureService(t.Context(), "svc_selected", controlv1.UpdateServiceRequest{
		Protocol: controlv1.ServiceProtocolHTTP, ExpectedTrustRevision: 7, UnconditionalConfiguration: new(true),
		Configuration: &controlv1.ProjectServiceConfiguration{Target: "private-listener.internal:3000"},
	})
	if err != nil {
		t.Fatal(err)
	}
}
