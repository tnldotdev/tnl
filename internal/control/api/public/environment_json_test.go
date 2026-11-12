package public

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestEnvironmentJSONRejectsExplicitNull(t *testing.T) {
	for _, test := range []struct {
		name, body string
		target     any
	}{
		{"root", `null`, &controlv1.CreateEnvironmentRequest{}},
		{"definition", `{"definition":null}`, &controlv1.CreateServiceDefinitionRequest{}},
		{"service", `{"definition":{"services":{"database":null}}}`, &controlv1.CreateServiceDefinitionRequest{}},
		{"protocol", `{"definition":{"services":{"database":{"protocol":null}}}}`, &controlv1.CreateServiceDefinitionRequest{}},
		{"create targets", `{"targets":null}`, &controlv1.CreateEnvironmentRequest{}},
		{"single apply targets", `{"targets":null}`, &controlv1.ApplyEnvironmentRequest{}},
		{"batch apply targets", `{"environments":[{"targets":null}]}`, &controlv1.ApplyEnvironmentsRequest{}},
		{"batch item", `{"environments":[null]}`, &controlv1.ApplyEnvironmentsRequest{}},
		{"target", `{"targets":{"database":null}}`, &controlv1.CreateEnvironmentRequest{}},
		{"address", `{"targets":{"database":{"address":null}}}`, &controlv1.CreateEnvironmentRequest{}},
		{"TLS", `{"targets":{"database":{"tls":null}}}`, &controlv1.CreateEnvironmentRequest{}},
		{"TLS hostname", `{"targets":{"database":{"tls":{"hostname":null}}}}`, &controlv1.CreateEnvironmentRequest{}},
		{"TLS digest", `{"targets":{"database":{"tls":{"digest":null}}}}`, &controlv1.CreateEnvironmentRequest{}},
		{"TLS CA", `{"targets":{"database":{"tls":{"ca_pem":null}}}}`, &controlv1.CreateEnvironmentRequest{}},
		{"discovery", `{"targets":{"database":{"discovery":null}}}`, &controlv1.CreateEnvironmentRequest{}},
		{"discovery region", `{"targets":{"database":{"discovery":{"region":null}}}}`, &controlv1.CreateEnvironmentRequest{}},
		{"overwritten null", `{"targets":null,"targets":{}}`, &controlv1.ApplyEnvironmentRequest{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			if err := decodeEnvironmentJSON(httptest.NewRecorder(), request, test.target); err == nil {
				t.Fatal("explicit null was accepted as an omitted or zero value")
			}
		})
	}
}

func TestEnvironmentJSONKeepsOmissionAndEmptyTLSObjectDistinct(t *testing.T) {
	var omitted controlv1.ApplyEnvironmentRequest
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"team_id":"team","definition_revision":1,"expected_revision":1}`))
	if err := decodeEnvironmentJSON(httptest.NewRecorder(), request, &omitted); err != nil || omitted.Targets != nil {
		t.Fatal("omitted replacement targets no longer retain approvals", err)
	}
	var explicit controlv1.ApplyEnvironmentRequest
	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"targets":{"database":{"address":"db.internal:5432","tls":{}}}}`))
	if err := decodeEnvironmentJSON(httptest.NewRecorder(), request, &explicit); err != nil || explicit.Targets == nil || (*explicit.Targets)["database"].Tls == nil {
		t.Fatal("empty TLS object no longer requests verified system trust", err)
	}
	var text controlv1.CreateEnvironmentRequest
	request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"null"}`))
	if err := decodeEnvironmentJSON(httptest.NewRecorder(), request, &text); err != nil || text.Name != "null" {
		t.Fatal("literal text was mistaken for a JSON null", err)
	}
}

func TestEnvironmentJSONRetainsStrictDecodingAndSizeBound(t *testing.T) {
	for _, body := range []string{
		`{"unexpected":true}`,
		`{"definition":{"services":{"database":{"protocol":"postgres","target":"private"}}}}`,
		`{} {}`,
		`{`,
		strings.Repeat(" ", int(environmentRequestBodyLimit)+1) + `{}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		var target controlv1.CreateServiceDefinitionRequest
		if err := decodeEnvironmentJSON(httptest.NewRecorder(), request, &target); err == nil {
			t.Fatal("unknown fields, invalid JSON, or an oversized body were accepted")
		}
	}
}
