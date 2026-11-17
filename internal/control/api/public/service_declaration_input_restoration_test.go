package public

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"go.yaml.in/yaml/v3"
)

type serviceDeclarationInputRestorationStore struct {
	ServiceStore
	calls         int
	metadata      controlstate.ServiceMetadata
	configuration *controlstate.ProjectServiceConfiguration
}

func (s *serviceDeclarationInputRestorationStore) record(metadata controlstate.ServiceMetadata, configuration *controlstate.ProjectServiceConfiguration) (controlstate.ServiceRecord, error) {
	s.calls++
	s.metadata, s.configuration = metadata, configuration
	return controlstate.ServiceRecord{ID: "svc_aaaaaaaaaaaaaaaaaaaaaa", Name: "declaration", ServiceMetadata: metadata}, nil
}

func (s *serviceDeclarationInputRestorationStore) CreateServiceAt(_ context.Context, team, actor, name, key string, _ controlstate.ServicePlacement, _ time.Time, metadata controlstate.ServiceMetadata, configuration *controlstate.ProjectServiceConfiguration) (controlstate.ServiceRecord, error) {
	if team != "team_1" || actor != testControlReadPrincipal().identityID || name != "declaration" || key != "operation" {
		panic("declaration creation changed the authenticated scope")
	}
	return s.record(metadata, configuration)
}

func (s *serviceDeclarationInputRestorationStore) ConfigureService(_ context.Context, service, actor string, metadata controlstate.ServiceMetadata, configuration *controlstate.ProjectServiceConfiguration, conditions controlstate.ServiceUpdateConditions, _ time.Time) (controlstate.ServiceRecord, error) {
	if service != "svc_aaaaaaaaaaaaaaaaaaaaaa" || actor != testControlReadPrincipal().identityID || metadata.TrustRevision != 7 ||
		metadata.PublisherPool || conditions.ConfigurationDigest != "" || conditions.PublisherPool != nil ||
		conditions.UnconditionalConfiguration != (configuration != nil) {
		panic("declaration replacement changed the authenticated scope or conditions")
	}
	return s.record(metadata, configuration)
}

func serviceDeclarationInputRestorationBody(operation, protocol, configuration string) string {
	body := fmt.Sprintf(`{"protocol":%q,"publisher_pool":false`, protocol)
	if operation == "create" {
		body += `,"team_id":"team_1","name":"declaration"`
	} else {
		body += `,"expected_trust_revision":"7"`
	}
	if configuration != "" {
		body += `,"configuration":` + configuration
		if operation != "create" {
			body += `,"unconditional_configuration":true`
		}
	}
	return body + "}"
}

func callServiceDeclarationInputRestoration(t *testing.T, operation, protocol, configuration, suffix string) (*httptest.ResponseRecorder, *serviceDeclarationInputRestorationStore) {
	t.Helper()
	store := &serviceDeclarationInputRestorationStore{}
	h := &handler{dependencies: Stores{Services: store}, authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
	method, path := http.MethodPost, "/v1/services"
	if operation != "create" {
		method, path = http.MethodPut, "/v1/services/svc_aaaaaaaaaaaaaaaaaaaaaa"
	}
	body := serviceDeclarationInputRestorationBody(operation, protocol, configuration) + suffix
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Idempotency-Key", "operation")
	response := httptest.NewRecorder()
	if operation == "create" {
		h.CreateService(response, request, controlv1.CreateServiceParams{})
	} else {
		h.ConfigureService(response, request, "svc_aaaaaaaaaaaaaaaaaaaaaa")
	}
	return response, store
}

func TestServiceDeclarationInputRestorationRejectsInvalidBeforeMutation(t *testing.T) {
	tooMany := make([]string, 257)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("2001:db8::%x", index+1)
	}
	encoded, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"create", "configure"} {
		for _, test := range []struct {
			name, configuration, suffix string
		}{
			{"null declaration", `null`, ""},
			{"null target", `{"target":null}`, ""},
			{"null PQ", `{"target":"app","require_post_quantum":null}`, ""},
			{"null HTTP", `{"target":"app","http":null}`, ""},
			{"null access", `{"target":"app","http":{"access":null}}`, ""},
			{"null mode", `{"target":"app","http":{"access":{"mode":null}}}`, ""},
			{"null IP", `{"target":"app","http":{"access":{"ip":null}}}`, ""},
			{"null IP entry", `{"target":"app","http":{"access":{"ip":[null]}}}`, ""},
			{"null limit", `{"target":"app","http":{"limits":{"total":null}}}`, ""},
			{"empty IP", `{"target":"app","http":{"access":{"ip":[]}}}`, ""},
			{"mapped prefix outside IPv4", `{"target":"app","http":{"access":{"ip":["::ffff:192.0.2.1/95"]}}}`, ""},
			{"invalid IP", `{"target":"app","http":{"access":{"ip":["invalid"]}}}`, ""},
			{"zoned IP", `{"target":"app","http":{"access":{"ip":["fe80::1%en0"]}}}`, ""},
			{"257 prefixes", `{"target":"app","http":{"access":{"ip":` + string(encoded) + `}}}`, ""},
			{"unknown field", `{"target":"app","credential":"private-declaration-value"}`, ""},
			{"trailing value", `{"target":"app"}`, " {}"},
		} {
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				response, store := callServiceDeclarationInputRestoration(t, operation, "http", test.configuration, test.suffix)
				if response.Code != http.StatusBadRequest {
					t.Errorf("invalid declaration status=%d, want 400: %s", response.Code, response.Body.String())
				}
				if store.calls != 0 {
					t.Errorf("invalid declaration reached mutation %d times", store.calls)
				}
				var problem controlv1.Problem
				if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
					t.Error("decode invalid declaration problem", err)
				} else if problem.Code != controlv1.InvalidRequest {
					t.Errorf("invalid declaration problem=%s, want invalid_request", problem.Code)
				}
				if strings.Contains(response.Body.String(), "private-declaration-value") {
					t.Error("declaration rejection exposed private input")
				}
				if test.name == "257 prefixes" && !strings.Contains(response.Body.String(), "256 normalized") {
					t.Error("limit error did not name the normalized-prefix count", response.Body.String())
				}
			})
		}
	}
}

func TestServiceDeclarationInputRestorationNormalizesAndPreservesOmission(t *testing.T) {
	maximum, canonical := make([]string, 256), make([]string, 256)
	for index := range maximum {
		maximum[index] = fmt.Sprintf("2001:db8::%x", index+1)
		canonical[index] = maximum[index] + "/128"
	}
	slices.Sort(canonical)
	encoded, err := json.Marshal(maximum)
	if err != nil {
		t.Fatal(err)
	}
	withDuplicates, err := json.Marshal(append(slices.Clone(maximum), maximum[0], maximum[0]+"/128"))
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"create", "configure"} {
		for _, test := range []struct {
			name, protocol, configuration, target string
			http                                  bool
			ip                                    []string
			postQuantum                           *bool
		}{
			{
				name: "duplicate masked prefix", protocol: "http", target: "app", http: true,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted","ip":["192.0.2.9/24","192.0.2.0/24"]}}}`,
				ip:            []string{"192.0.2.0/24"},
			},
			{
				name: "duplicate address prefix", protocol: "http", target: "app", http: true,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted","ip":["192.0.2.1","192.0.2.1/32"]}}}`,
				ip:            []string{"192.0.2.1/32"},
			},
			{
				name: "duplicate mapped address", protocol: "http", target: "app", http: true,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted","ip":["192.0.2.1","::ffff:192.0.2.1"]}}}`,
				ip:            []string{"192.0.2.1/32"},
			},
			{
				name: "duplicate mapped prefix", protocol: "http", target: "app", http: true,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted","ip":["192.0.2.0/24","::ffff:192.0.2.9/120"]}}}`,
				ip:            []string{"192.0.2.0/24"},
			},
			{
				name: "overlapping network and single IP", protocol: "http", target: "app", http: true,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted","ip":["192.0.2.1","192.0.2.9/24"]}}}`,
				ip:            []string{"192.0.2.0/24", "192.0.2.1/32"},
			},
			{
				name: "256 prefixes plus duplicates", protocol: "http", target: "app", http: true, ip: canonical,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted","ip":` + string(withDuplicates) + `}}}`,
			},
			{
				name: "unmasked dual stack and PQ true", protocol: "http", target: "localhost:4000", http: true, postQuantum: new(true),
				configuration: `{"target":"localhost:4000","require_post_quantum":true,"http":{"access":{"mode":"restricted","ip":["2001:db8::9/64","192.0.2.9/24"]}}}`,
				ip:            []string{"192.0.2.0/24", "2001:db8::/64"},
			},
			{
				name: "omitted IP in complete declaration", protocol: "http", target: "app", http: true,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted"}}}`,
			},
			{
				name: "mapped address and prefix", protocol: "http", target: "app", http: true,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted","ip":["::ffff:192.0.2.9/120","::ffff:198.51.100.7"]}}}`,
				ip:            []string{"192.0.2.0/24", "198.51.100.7/32"},
			},
			{
				name: "mapped IPv4 universe", protocol: "http", target: "app", http: true,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted","ip":["::ffff:192.0.2.9/96"]}}}`,
				ip:            []string{"0.0.0.0/0"},
			},
			{
				name: "explicit PQ false", protocol: "http", target: "app", postQuantum: new(false),
				configuration: `{"target":"app","require_post_quantum":false}`,
			},
			{name: "omitted declaration", protocol: "http"},
			{
				name: "native declaration stays native", protocol: "tcp", target: "database.internal:5432",
				configuration: `{"protocol":"tcp","target":"database.internal:5432"}`,
			},
			{
				name: "256 prefixes", protocol: "http", target: "app", http: true, ip: canonical,
				configuration: `{"target":"app","http":{"access":{"mode":"restricted","ip":` + string(encoded) + `}}}`,
			},
		} {
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				response, store := callServiceDeclarationInputRestoration(t, operation, test.protocol, test.configuration, "")
				want := http.StatusOK
				if operation == "create" {
					want = http.StatusCreated
				}
				if response.Code != want || store.calls != 1 {
					t.Fatalf("valid declaration status=%d calls=%d, want %d/1: %s", response.Code, store.calls, want, response.Body.String())
				}
				if store.metadata.Protocol != test.protocol {
					t.Fatal("declaration decoding changed the approved protocol", store.metadata.Protocol)
				}
				saved := store.configuration
				if test.configuration == "" {
					if saved != nil {
						t.Fatal("omitting the whole declaration invented replacement intent")
					}
					return
				}
				if saved == nil || saved.Target != test.target || !reflect.DeepEqual(saved.RequirePostQuantum, test.postQuantum) {
					t.Fatal("declaration decoding changed the desired target or explicit PQ presence")
				}
				if (saved.HTTP != nil) != test.http {
					t.Fatal("declaration decoding invented or lost HTTP settings")
				}
				if test.http && (saved.HTTP.Access == nil || saved.HTTP.Access.Mode != "restricted" || !reflect.DeepEqual(saved.HTTP.Access.IP, test.ip)) {
					t.Fatal("declaration did not normalize the exact policy before strict configuration decoding")
				}
				if test.protocol == "tcp" && saved.Protocol != "tcp" {
					t.Fatal("native declaration acquired HTTP protocol")
				}
			})
		}
	}
}

func TestServiceDeclarationExactBodyLimitBeforeMutation(t *testing.T) {
	const limit = 2 << 20
	const configuration = `{"target":"private-body-boundary.internal:3000"}`
	for _, operation := range []string{"create", "configure"} {
		body := serviceDeclarationInputRestorationBody(operation, "http", configuration)
		for _, size := range []int{limit - 1, limit, limit + 1} {
			t.Run(fmt.Sprintf("%s/%d", operation, size), func(t *testing.T) {
				// trailing whitespace is valid JSON input, so only the actual
				// request-body bound can reject the one-byte-over case.
				suffix := strings.Repeat(" ", size-len(body))
				response, store := callServiceDeclarationInputRestoration(t, operation, "http", configuration, suffix)
				if size <= limit {
					want := http.StatusOK
					if operation == "create" {
						want = http.StatusCreated
					}
					if response.Code != want || store.calls != 1 || store.configuration == nil ||
						store.configuration.Target != "private-body-boundary.internal:3000" {
						t.Fatal("legal boundary body did not reach its exact mutation once", response.Code, store.calls)
					}
					return
				}
				var problem controlv1.Problem
				if response.Code != http.StatusBadRequest || store.calls != 0 ||
					json.Unmarshal(response.Body.Bytes(), &problem) != nil || problem.Code != controlv1.InvalidRequest {
					t.Fatal("over-limit body reached mutation or lost its invalid-request problem", response.Code, store.calls)
				}
				if strings.Contains(response.Body.String(), "private-body-boundary.internal") {
					t.Fatal("over-limit body rejection exposed private declaration input")
				}
			})
		}
	}
}

func TestServiceIPNormalizationMatchesConfiguration(t *testing.T) {
	const access = `{"ip":["::ffff:192.0.2.1","192.0.2.1/32","192.0.2.9/24","2001:0DB8::9/64","2001:db8::/64"]}`
	want := []string{"192.0.2.0/24", "192.0.2.1/32", "2001:db8::/64"}
	var configured config.Access
	if err := json.Unmarshal([]byte(access), &configured); err != nil {
		t.Fatal(err)
	}
	var yamlAccess config.Access
	if err := yaml.Unmarshal([]byte(access), &yamlAccess); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"create", "configure"} {
		response, store := callServiceDeclarationInputRestoration(t, operation, "http",
			`{"target":"app","http":{"access":`+access+`}}`, "")
		if store.calls != 1 || store.configuration == nil {
			t.Fatal("equivalent API policy did not reach mutation", response.Code, response.Body.String())
		}
		saved := store.configuration.HTTP.Access
		if !slices.Equal(saved.IP, want) || !slices.Equal(configured.IP, want) || !slices.Equal(yamlAccess.IP, want) ||
			saved.VisitorMode() != "restricted" || configured.VisitorMode() != "restricted" || yamlAccess.VisitorMode() != "restricted" {
			t.Fatal("config/API normalization changed prefixes or granted anonymous access", configured, yamlAccess, saved)
		}
	}
}
