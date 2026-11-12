package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const environmentPublisherGrantTestPath = "/v1/projects/accounts/environments/env_AAAAAAAAAAAAAAAAAAAAAA/publishers/pub_BBBBBBBBBBBBBBBBBBBBBB/services/svc_CCCCCCCCCCCCCCCCCCCCCC/grant"
const environmentPublisherGrantTestTeam = "tm_DDDDDDDDDDDDDDDDDDDDDD"
const environmentPublisherGrantTestID = "pgrant_EEEEEEEEEEEEEEEEEEEEEE"

type environmentPublisherGrantRejectingStore struct{ authentications, operations int }

func (s *environmentPublisherGrantRejectingStore) AuthenticateEnvironmentPublisherManager(context.Context, credentials.AccessToken) (controlstate.EnvironmentPublisherManager, error) {
	s.authentications++
	return controlstate.EnvironmentPublisherManager{}, controlstate.ErrControlAuthentication
}
func (s *environmentPublisherGrantRejectingStore) GetEnvironmentPublisherGrant(context.Context, controlstate.InspectEnvironmentPublisherGrantRequest) (controlstate.EnvironmentPublisherGrantState, error) {
	s.operations++
	return controlstate.EnvironmentPublisherGrantState{}, controlstate.ErrControlAuthentication
}
func (s *environmentPublisherGrantRejectingStore) AuthorizeEnvironmentPublisherService(context.Context, controlstate.AuthorizeEnvironmentPublisherServiceRequest) (controlstate.EnvironmentPublisherGrantAuthorization, error) {
	s.operations++
	return controlstate.EnvironmentPublisherGrantAuthorization{}, controlstate.ErrControlAuthentication
}
func (s *environmentPublisherGrantRejectingStore) RevokeEnvironmentPublisherGrant(context.Context, controlstate.RevokeEnvironmentPublisherGrantRequest) error {
	s.operations++
	return controlstate.ErrControlAuthentication
}

func environmentPublisherGrantTestBody(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(controlv1.AuthorizeEnvironmentPublisherServiceRequest{TeamId: environmentPublisherGrantTestTeam, ExpectedRevision: 2,
		ExpectedConfigurationHash: strings.Repeat("a", 64), ExpectedPreviousGrantId: nil, IdempotencyKey: "explicit-intent"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"expected_previous_grant_id":null`) {
		t.Fatal("generated client model erased required explicit null")
	}
	return string(data)
}

func TestEnvironmentPublisherGrantRequiresExplicitStore(t *testing.T) {
	handler, err := NewHandler(Config{}, Stores{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ method, path string }{
		{http.MethodGet, environmentPublisherGrantTestPath + "?team_id=" + environmentPublisherGrantTestTeam},
		{http.MethodPost, environmentPublisherGrantTestPath},
		{http.MethodDelete, environmentPublisherGrantTestPath + "/" + environmentPublisherGrantTestID + "?team_id=" + environmentPublisherGrantTestTeam + "&expected_revision=2&expected_configuration_hash=" + strings.Repeat("a", 64)},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, strings.NewReader(environmentPublisherGrantTestBody(t))))
		assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), http.StatusServiceUnavailable, controlv1.Unavailable)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing capability response may be cached")
		}
	}
}

func TestEnvironmentPublisherGrantJSONPresenceAndMalformedInputs(t *testing.T) {
	valid := environmentPublisherGrantTestBody(t)
	var base map[string]json.RawMessage
	if err := json.Unmarshal([]byte(valid), &base); err != nil {
		t.Fatal(err)
	}
	changed := func(field, raw string) string {
		copy := make(map[string]json.RawMessage, len(base))
		for key, value := range base {
			copy[key] = value
		}
		if raw == "" {
			delete(copy, field)
		} else {
			copy[field] = json.RawMessage(raw)
		}
		data, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	invalid := []string{"null", "[]", "{}", valid + "{}", valid + " null", strings.Replace(valid, "explicit-intent", "invalid-\xff", 1), strings.Repeat(" ", int(environmentPublisherGrantBodyLimit)) + valid,
		strings.TrimSuffix(valid, "}") + `,"idempotency_key":"duplicate"}`,
		changed("expected_previous_grant_id", ""), changed("expected_previous_grant_id", `""`), changed("expected_previous_grant_id", `"sgr_AAAAAAAAAAAAAAAAAAAAAA"`),
		changed("expected_previous_grant_id", "1"), changed("expected_previous_grant_id", "true"), changed("expected_previous_grant_id", "{}"), changed("expected_previous_grant_id", "[]"),
		changed("expected_revision", "1.5"), changed("expected_revision", "9223372036854775808"), changed("expected_revision", "0"), changed("expected_revision", "-1"),
		changed("expected_configuration_hash", `"`+strings.Repeat("A", 64)+`"`), changed("expected_configuration_hash", `"short"`),
		changed("team_id", `"team_AAAAAAAAAAAAAAAAAAAAAA"`), changed("team_id", "1"),
		changed("idempotency_key", `""`), changed("idempotency_key", `" trailing "`), changed("idempotency_key", `"embedded\u0000control"`),
		changed("idempotency_key", `"`+strings.Repeat("x", 129)+`"`), changed("idempotency_key", `"`+strings.Repeat("😀", 40)+`"`),
		changed("group_id", `"pgrp_AAAAAAAAAAAAAAAAAAAAAA"`), changed("TEAM_ID", `"`+environmentPublisherGrantTestTeam+`"`)}
	for _, field := range []string{"team_id", "expected_revision", "expected_configuration_hash", "idempotency_key"} {
		invalid = append(invalid, changed(field, "null"), changed(field, ""))
	}
	store := &environmentPublisherGrantRejectingStore{}
	handler, err := NewHandler(Config{}, Stores{EnvironmentPublisherGrants: store}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, input := range invalid {
		request := httptest.NewRequest(http.MethodPost, environmentPublisherGrantTestPath, strings.NewReader(input))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer sensitive-marker")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || response.Header().Get("Cache-Control") != "no-store" || store.authentications != 0 || store.operations != 0 {
			t.Fatalf("malformed input %d reached state or produced wrong response: %d, auth=%d, operations=%d", i, response.Code, store.authentications, store.operations)
		}
		if strings.Contains(response.Body.String(), "sensitive-marker") {
			t.Fatal("credential appeared in problem response")
		}
	}
	request := httptest.NewRequest(http.MethodPost, environmentPublisherGrantTestPath, strings.NewReader(valid))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Authorization", "Bearer sensitive-marker")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), http.StatusUnauthorized, controlv1.Unauthenticated)
	if store.authentications != 1 || store.operations != 0 {
		t.Fatal("explicit null did not reach exact credential authentication")
	}
}

func TestEnvironmentPublisherGrantCredentialCaptureForEveryOperation(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			store := &environmentPublisherGrantRejectingStore{}
			handler, err := NewHandler(Config{}, Stores{EnvironmentPublisherGrants: store}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			path := environmentPublisherGrantTestPath
			if method == http.MethodGet {
				path += "?team_id=" + environmentPublisherGrantTestTeam
			} else if method == http.MethodDelete {
				path += "/" + environmentPublisherGrantTestID + "?team_id=" + environmentPublisherGrantTestTeam + "&expected_revision=2&expected_configuration_hash=" + strings.Repeat("a", 64)
			}
			for _, authorization := range []string{"", "Bearer sensitive-marker"} {
				request := httptest.NewRequest(method, path, strings.NewReader(environmentPublisherGrantTestBody(t)))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Authorization", authorization)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), http.StatusUnauthorized, controlv1.Unauthenticated)
				if store.operations != 0 || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("WWW-Authenticate") == "" || strings.Contains(response.Body.String(), "sensitive-marker") {
					t.Fatal("operation bypassed credential capture or leaked/cacheable failure")
				}
			}
			if store.authentications != 1 {
				t.Fatal("operation did not invoke its explicit credential capture capability")
			}
		})
	}
}

func TestEnvironmentPublisherGrantMalformedPathAndQueryBeforeState(t *testing.T) {
	store := &environmentPublisherGrantRejectingStore{}
	handler, err := NewHandler(Config{}, Stores{EnvironmentPublisherGrants: store}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	query := "?team_id=" + environmentPublisherGrantTestTeam
	deletePath := environmentPublisherGrantTestPath + "/" + environmentPublisherGrantTestID
	deleteQuery := query + "&expected_revision=2&expected_configuration_hash=" + strings.Repeat("a", 64)
	for _, test := range []struct{ method, path string }{
		{http.MethodGet, environmentPublisherGrantTestPath},
		{http.MethodGet, environmentPublisherGrantTestPath + query + "&team_id=" + environmentPublisherGrantTestTeam},
		{http.MethodGet, environmentPublisherGrantTestPath + query + "&group_id=not-a-scope"},
		{http.MethodGet, strings.Replace(environmentPublisherGrantTestPath, "env_", "pub_", 1) + query},
		{http.MethodGet, strings.Replace(environmentPublisherGrantTestPath, "svc_", "pub_", 1) + query},
		{http.MethodGet, strings.Replace(environmentPublisherGrantTestPath, "pub_", "pgrp_", 1) + query},
		{http.MethodGet, strings.Replace(environmentPublisherGrantTestPath, "accounts", "UPPER", 1) + query},
		{http.MethodDelete, deletePath + query},
		{http.MethodDelete, deletePath + strings.Replace(deleteQuery, "expected_revision=2", "expected_revision=1.5", 1)},
		{http.MethodDelete, deletePath + strings.Replace(deleteQuery, "expected_revision=2", "expected_revision=9223372036854775808", 1)},
		{http.MethodDelete, deletePath + strings.Replace(deleteQuery, "expected_revision=2", "expected_revision=0", 1)},
		{http.MethodDelete, deletePath + strings.Replace(deleteQuery, strings.Repeat("a", 64), "short", 1)},
		{http.MethodDelete, strings.Replace(deletePath, "pgrant_", "sgr_", 1) + deleteQuery},
		{http.MethodPost, environmentPublisherGrantTestPath + query},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader(environmentPublisherGrantTestBody(t)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer sensitive-marker")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertEnvironmentHTTPProblem(t, response.Code, response.Body.Bytes(), http.StatusBadRequest, controlv1.InvalidRequest)
		if response.Header().Get("Cache-Control") != "no-store" || store.authentications != 0 || store.operations != 0 {
			t.Fatal("malformed selection reached state or may be cached", test.path)
		}
	}
}
