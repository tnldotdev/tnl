package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceConfigurationStore struct {
	ServiceStore
	calls         int
	configuration *controlstate.ProjectServiceConfiguration
	digest        string
	conditions    controlstate.ServiceUpdateConditions
	err           error
}

func (s *serviceConfigurationStore) ConfigureService(_ context.Context, service, actor string, metadata controlstate.ServiceMetadata, configuration *controlstate.ProjectServiceConfiguration, conditions controlstate.ServiceUpdateConditions, _ time.Time) (controlstate.ServiceRecord, error) {
	s.calls++
	if service != "svc_aaaaaaaaaaaaaaaaaaaaaa" || actor != testPublicURLReadPrincipal().identityID ||
		metadata.Protocol != "http" || metadata.TrustRevision != 7 || metadata.PublisherPool || metadata.TLS != nil {
		panic("configure changed authenticated scope or approved metadata")
	}
	s.configuration = configuration
	s.digest = conditions.ConfigurationDigest
	s.conditions = conditions
	return controlstate.ServiceRecord{ID: service, ServiceMetadata: metadata}, s.err
}

func TestConfigureServicePoolConditionWire(t *testing.T) {
	const settings = `"protocol":"http","publisher_pool":false,"expected_trust_revision":"7"`
	for _, test := range []struct {
		name, condition string
		expected        *bool
		err             error
		status, calls   int
	}{
		{"omitted", "", nil, nil, 200, 1},
		{"observed false", `,"expected_publisher_pool":false`, new(false), nil, 200, 1},
		{"observed true differs from desired", `,"expected_publisher_pool":true`, new(true), nil, 200, 1},
		{"stale", `,"expected_publisher_pool":true`, new(true), controlstate.ErrServiceConflict, 409, 1},
		{"null", `,"expected_publisher_pool":null`, nil, nil, 400, 0},
		{"string", `,"expected_publisher_pool":"false"`, nil, nil, 400, 0},
		{"number", `,"expected_publisher_pool":0`, nil, nil, 400, 0},
		{"object", `,"expected_publisher_pool":{}`, nil, nil, 400, 0},
		{"array", `,"expected_publisher_pool":[]`, nil, nil, 400, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &serviceConfigurationStore{err: test.err}
			h := &handler{store: store, dependencies: Stores{Services: store}, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
			request := httptest.NewRequest(http.MethodPut, "/v1/services/svc_aaaaaaaaaaaaaaaaaaaaaa", strings.NewReader("{"+settings+test.condition+"}"))
			request.Header.Set("Authorization", "Bearer access-token")
			response := httptest.NewRecorder()
			h.ConfigureService(response, request, "svc_aaaaaaaaaaaaaaaaaaaaaa")
			if response.Code != test.status || store.calls != test.calls {
				t.Fatal("pool condition decoding or conflict status changed", response.Code, store.calls, response.Body.String())
			}
			actual := store.conditions.PublisherPool
			if (actual == nil) != (test.expected == nil) || actual != nil && *actual != *test.expected ||
				store.conditions.ConfigurationDigest != "" || store.configuration != nil {
				t.Fatal("pool condition was dropped, inferred from desired intent, or coupled to a declaration")
			}
		})
	}
}

func TestConfigureServiceDeclarationWire(t *testing.T) {
	const settings = `"protocol":"http","publisher_pool":false,"expected_trust_revision":"7"`
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name, body string
		err        error
		status     int
		calls      int
		declared   bool
	}{
		{"retain", `{` + settings + `}`, nil, 200, 1, false},
		{"replace", `{` + settings + `,"configuration":{"target":"localhost:4000","http":{"access":{"mode":"anonymous"},"limits":{"total":11}}}}`, nil, 200, 1, true},
		{"conditional", `{` + settings + `,"configuration":{"target":"localhost:4000"},"expected_configuration_digest":"` + digest + `"}`, nil, 200, 1, true},
		{"conditional pool", `{` + settings + `,"configuration":{"target":"localhost:4000"},"expected_configuration_digest":"` + digest + `","expected_publisher_pool":true}`, nil, 200, 1, true},
		{"conflict", `{` + settings + `,"configuration":{"target":"localhost:4000"}}`, controlstate.ErrServiceConflict, 409, 1, true},
		{"missing replacement", `{` + settings + `,"expected_configuration_digest":"` + digest + `"}`, nil, 400, 0, false},
		{"empty digest", `{` + settings + `,"configuration":{"target":"localhost:4000"},"expected_configuration_digest":""}`, nil, 400, 0, false},
		{"null digest", `{` + settings + `,"configuration":{"target":"localhost:4000"},"expected_configuration_digest":null}`, nil, 400, 0, false},
		{"uppercase digest", `{` + settings + `,"configuration":{"target":"localhost:4000"},"expected_configuration_digest":"` + strings.ToUpper(digest) + `"}`, nil, 400, 0, false},
		{"null", `{` + settings + `,"configuration":null}`, nil, 400, 0, false},
		{"unknown", `{` + settings + `,"configuration":{"target":"localhost:4000","credential":"secret"}}`, nil, 400, 0, false},
		{"endpoint", `{` + settings + `,"endpoint":{"hostname":"ignored.example"}}`, nil, 400, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &serviceConfigurationStore{err: test.err}
			h := &handler{store: store, dependencies: Stores{Services: store}, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
			request := httptest.NewRequest(http.MethodPut, "/v1/services/svc_aaaaaaaaaaaaaaaaaaaaaa", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer access-token")
			response := httptest.NewRecorder()
			h.ConfigureService(response, request, "svc_aaaaaaaaaaaaaaaaaaaaaa")
			if response.Code != test.status || store.calls != test.calls || (store.configuration != nil) != test.declared {
				t.Fatal("configure decoding or forwarding changed", response.Code, store.calls, response.Body.String())
			}
			if test.declared && store.configuration.Target != "localhost:4000" {
				t.Fatal("configure discarded the declaration")
			}
			if test.name == "conditional" && (store.digest != digest || store.conditions.PublisherPool != nil) {
				t.Fatal("configure discarded its exact configuration condition or inferred a pool condition")
			}
			if test.name == "conditional pool" && (store.digest != digest || store.conditions.PublisherPool == nil || !*store.conditions.PublisherPool) {
				t.Fatal("configure discarded an independent configuration or pool condition")
			}
			if test.name == "replace" && (store.configuration.HTTP == nil || store.configuration.HTTP.Access.Mode != "anonymous" ||
				store.configuration.HTTP.Limits == nil || *store.configuration.HTTP.Limits.Total != 11) {
				t.Fatal("configure discarded policy or request limits")
			}
			if strings.Contains(response.Body.String(), "localhost") || strings.Contains(response.Body.String(), "secret") {
				t.Fatal("configure response exposed private declaration data")
			}
			if response.Code == 200 {
				var service controlv1.Service
				if err := json.Unmarshal(response.Body.Bytes(), &service); err != nil || service.Id != "svc_aaaaaaaaaaaaaaaaaaaaaa" {
					t.Fatal("configure replaced the service identity", err)
				}
			}
		})
	}
}

func (s *serviceConfigurationStore) GetServiceConfiguration(_ context.Context, service, actor string) (*controlstate.ProjectServiceConfiguration, string, error) {
	s.calls++
	if service != "svc_aaaaaaaaaaaaaaaaaaaaaa" || actor != testPublicURLReadPrincipal().identityID {
		panic("configuration read changed its authenticated service manager")
	}
	return s.configuration, s.digest, s.err
}

func TestGetServiceConfigurationWire(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name          string
		configuration *controlstate.ProjectServiceConfiguration
		err           error
		status        int
	}{
		{"absent", nil, nil, 204},
		{"present", &controlstate.ProjectServiceConfiguration{Target: "private-listener.internal:3000"}, nil, 200},
		{"denied", nil, controlstate.ErrServiceAccess, 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &serviceConfigurationStore{configuration: test.configuration, digest: digest, err: test.err}
			h := &handler{store: store, dependencies: Stores{Services: store}, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
			request := httptest.NewRequest(http.MethodGet, "/v1/services/svc_aaaaaaaaaaaaaaaaaaaaaa/configuration", nil)
			request.Header.Set("Authorization", "Bearer access-token")
			response := httptest.NewRecorder()
			h.GetServiceConfiguration(response, request, "svc_aaaaaaaaaaaaaaaaaaaaaa")
			if response.Code != test.status || store.calls != 1 || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("protected read changed its status or cache policy", response.Code)
			}
			if test.err != nil {
				if response.Header().Get("ETag") != "" {
					t.Fatal("denied read exposed a configuration digest")
				}
				return
			}
			if response.Header().Get("ETag") != strconv.Quote(digest) {
				t.Fatal("read lost its strong configuration ETag")
			}
			if test.status == 204 {
				if response.Body.Len() != 0 {
					t.Fatal("declaration-free read returned a body")
				}
			} else {
				var declaration controlv1.ProjectServiceConfiguration
				if err := json.Unmarshal(response.Body.Bytes(), &declaration); err != nil || declaration.Target != test.configuration.Target {
					t.Fatal("read returned a wrapper instead of the defining declaration", err)
				}
			}
		})
	}
}
