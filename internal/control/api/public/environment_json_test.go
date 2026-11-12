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
		{"collection create root", `null`, &controlv1.CreateCollectionRequest{}},
		{"collection name", `{"name":null}`, &controlv1.CreateCollectionRequest{}},
		{"collection default", `{"default_definition_revision":null}`, &controlv1.CreateCollectionRequest{}},
		{"collection update expected", `{"expected_revision":null}`, &controlv1.UpdateCollectionDefaultRequest{}},
		{"collection update definition", `{"definition_revision":null}`, &controlv1.UpdateCollectionDefaultRequest{}},
		{"environment collection", `{"collection_id":null}`, &controlv1.CreateEnvironmentRequest{}},
		{"environment expected collection", `{"expected_collection_revision":null}`, &controlv1.CreateEnvironmentRequest{}},
		{"environment definition", `{"definition_revision":null}`, &controlv1.CreateEnvironmentRequest{}},
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

func TestEnvironmentCreationCollectionSelectionPreservesWirePresence(t *testing.T) {
	for _, test := range []struct {
		name, selection      string
		valid                bool
		definition, expected int64
		collection           string
	}{
		{"independent", `"definition_revision":3`, true, 3, 0, ""},
		{"default", `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":1`, true, 0, 1, "coll_AAAAAAAAAAAAAAAAAAAAAA"},
		{"explicit override", `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":1,"definition_revision":3`, true, 3, 1, "coll_AAAAAAAAAAAAAAAAAAAAAA"},
		{name: "missing selection", selection: `"project_label":"environment"`},
		{name: "zero independent", selection: `"definition_revision":0`},
		{name: "zero with collection", selection: `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":1,"definition_revision":0`},
		{name: "negative", selection: `"definition_revision":-1`},
		{name: "collection alone", selection: `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA"`},
		{name: "expected alone", selection: `"expected_collection_revision":1`},
		{name: "expected with independent", selection: `"definition_revision":3,"expected_collection_revision":1`},
		{name: "zero expected", selection: `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":0`},
		{name: "negative expected", selection: `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":-1`},
		{name: "empty collection", selection: `"collection_id":"","expected_collection_revision":1`},
		{name: "wrong ID kind", selection: `"collection_id":"env_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":1`},
		{name: "null definition", selection: `"definition_revision":null`},
		{name: "null collection", selection: `"collection_id":null,"expected_collection_revision":1`},
		{name: "null expected", selection: `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":null`},
		{name: "string revision", selection: `"definition_revision":"3"`},
		{name: "fractional revision", selection: `"definition_revision":1.5`},
		{name: "overflow revision", selection: `"definition_revision":9223372036854775808`},
		{name: "numeric collection", selection: `"collection_id":3,"expected_collection_revision":1`},
		{name: "string expected", selection: `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":"1"`},
		{name: "fractional expected", selection: `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":1.5`},
		{name: "overflow expected", selection: `"collection_id":"coll_AAAAAAAAAAAAAAAAAAAAAA","expected_collection_revision":9223372036854775808`},
		{name: "unknown field", selection: `"definition_revision":3,"membership":"sensitive-marker"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := `{"team_id":"team","source_fingerprint":"` + strings.Repeat("a", 64) + `","name":"environment","idempotency_key":"K","targets":{"api":{"address":"api.internal:3000"}},` + test.selection + `}`
			var input controlv1.CreateEnvironmentRequest
			err := decodeEnvironmentJSON(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &input)
			if err != nil {
				if test.valid {
					t.Fatal(err)
				}
				return
			}
			result, err := environmentCreationFromAPI(t.Context(), input)
			if !test.valid {
				if err == nil {
					t.Fatal("invalid wire selection reached state conversion", result)
				}
				return
			}
			if err != nil || result.DefinitionRevision != test.definition || result.CollectionID != test.collection || result.ExpectedCollectionRevision != test.expected || result.Targets["api"].Address != "api.internal:3000" {
				t.Fatal("wire selection lost presence, exact revision or approved target", result, err)
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
