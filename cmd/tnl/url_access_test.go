package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestURLAccessUsesSameServiceAndFreshDeclarationAfterConflict(t *testing.T) {
	const id = "svc_0123456789abcdefghijkl"
	current := controlv1.Service{Id: id, TeamId: "tm_selected", Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 4, PublisherPool: true,
		Endpoint:  &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true},
		TargetTls: &controlv1.ServiceTargetTLS{Hostname: "target.internal", Digest: strings.Repeat("b", 64), System: true}}
	declaration := controlv1.ProjectServiceConfiguration{Target: "target.internal:8443", DomainId: new("dom_selected"), Hostname: new("web.example.test"), Public: new(true),
		Protocol: new(controlv1.ServiceProtocolHTTP), RequirePostQuantum: new(true), TargetTls: &controlv1.ProjectTargetTLS{Hostname: "target.internal", Digest: strings.Repeat("b", 64)},
		Access:  &controlv1.ProjectServiceAccess{Team: true},
		Traffic: &controlv1.TrafficSelection{TotalConnections: new(int64(91))},
		Http: &controlv1.ProjectServiceHTTP{Open: new(false), Limits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(9), Total: new(44)},
			Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.VisitorAccessMode("restricted")), Ip: &[]string{"192.0.2.0/24"}}}}
	reads, writes := 0, 0
	digest := "sha256:" + strings.Repeat("a", 64)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer manager" {
			t.Error("configuration management did not use its control session")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/services/" + id:
			_ = json.NewEncoder(w).Encode(current)
		case "GET /v1/services/" + id + "/configuration":
			reads++
			w.Header().Set("ETag", `"`+digest+`"`)
			_ = json.NewEncoder(w).Encode(declaration)
		case "PUT /v1/services/" + id:
			writes++
			var body controlv1.UpdateServiceRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.ExpectedConfigurationDigest == nil || *body.ExpectedConfigurationDigest != digest || body.ExpectedTrustRevision != current.TrustRevision ||
				body.ExpectedPublisherPool == nil || *body.ExpectedPublisherPool != current.PublisherPool ||
				body.Protocol != current.Protocol || body.PublisherPool != current.PublisherPool || !reflect.DeepEqual(body.TargetTls, current.TargetTls) {
				t.Error("replacement lost its independent trust and declaration fences")
			}
			expected := declaration
			httpSettings := *declaration.Http
			httpSettings.Access = &controlv1.ProjectHTTPAccess{Mode: new(controlv1.VisitorAccessMode("anonymous")), Ip: &[]string{"203.0.113.0/24"}}
			expected.Http = &httpSettings
			if !reflect.DeepEqual(body.Configuration, &expected) {
				t.Error("HTTP access replacement changed unrelated saved intent")
			}
			if writes == 1 {
				declaration.Target = "concurrent-target.internal:8443"
				declaration.Http.Limits.Total = new(99)
				digest = "sha256:" + strings.Repeat("c", 64)
				current.TrustRevision++
				current.PublisherPool = false
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(controlv1.Problem{Code: controlv1.Conflict, Status: http.StatusConflict})
				return
			}
			_ = json.NewEncoder(w).Encode(current)
		default:
			t.Errorf("unexpected configuration operation: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	client, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("manager"))
	if err != nil {
		t.Fatal(err)
	}
	result, saved, err := replaceServiceHTTPAccess(t.Context(), client, controlv1.ServiceSummary{Id: current.Id, TeamId: current.TeamId}, "anonymous", []string{"203.0.113.0/24"})
	if err != nil || result.Id != id || result.PublisherPool || saved == nil || saved.Target != declaration.Target || reads != 2 || writes != 2 {
		t.Fatalf("same-ID access replacement: reads=%d writes=%d err=%v", reads, writes, err)
	}
	var output bytes.Buffer
	if err := writeAccessPolicy(&output, result.Id, result.Endpoint, saved); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), declaration.Target) || strings.Contains(output.String(), current.TargetTls.Digest) || !strings.Contains(output.String(), "anonymous") {
		t.Fatal("access output leaked protected configuration or lost the requested mode")
	}
}

func TestURLAccessDoesNotInventMissingDeclarationAndBoundsConflicts(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing declaration", false: "conflicts"}[missing], func(t *testing.T) {
			const id = "svc_0123456789abcdefghijkl"
			item := controlv1.Service{Id: id, TeamId: "tm_selected", Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1}
			writes := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.Method + " " + r.URL.Path {
				case "GET /v1/services/" + id:
					_ = json.NewEncoder(w).Encode(item)
				case "GET /v1/services/" + id + "/configuration":
					w.Header().Set("ETag", `"sha256:`+strings.Repeat("a", 64)+`"`)
					if missing {
						w.WriteHeader(http.StatusNoContent)
					} else {
						_ = json.NewEncoder(w).Encode(controlv1.ProjectServiceConfiguration{Target: "127.0.0.1:3000"})
					}
				case "PUT /v1/services/" + id:
					writes++
					w.WriteHeader(http.StatusConflict)
					_ = json.NewEncoder(w).Encode(controlv1.Problem{Code: controlv1.Conflict, Status: http.StatusConflict})
				default:
					t.Errorf("access mutation changed selection or recreated a service: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			client, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("manager"))
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = replaceServiceHTTPAccess(t.Context(), client, controlv1.ServiceSummary{Id: item.Id, TeamId: item.TeamId}, "anonymous", nil)
			if missing {
				if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags || writes != 0 {
					t.Fatal("missing configuration caused guessed intent or a write", err)
				}
			} else if !errors.Is(err, clientcontrol.ErrStatusConflict) || writes != 3 {
				t.Fatalf("conflict retry count=%d err=%v", writes, err)
			}
		})
	}
}
