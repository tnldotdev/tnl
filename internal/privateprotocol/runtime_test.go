package privateprotocol

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func TestPrepareGoldenAndStrictRequestBounds(t *testing.T) {
	golden := `{"version":1,"directory":"/project","service":"web","framework":"node","owner":"0123456789abcdef0123456789abcdef","pid":123}`
	request := Prepare{Version: 1, Directory: "/project", Service: "web", Framework: "node", Owner: "0123456789abcdef0123456789abcdef", PID: 123}
	data, err := json.Marshal(request)
	if err != nil || string(data) != golden {
		t.Fatalf("golden = %s, %v", data, err)
	}
	for _, test := range []struct {
		body, origin string
		valid        bool
	}{{golden, "", true}, {golden + " {}", "", false}, {strings.Replace(golden, `"pid":123`, `"pid":123,"token":"secret"`, 1), "", false}, {golden, "https://app.example", false}, {strings.Repeat("x", MaxBytes+1), "", false}} {
		r := httptest.NewRequest("POST", "/v1/prepare", strings.NewReader(test.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", test.origin)
		var value Prepare
		if err := Decode(httptest.NewRecorder(), r, &value); (err == nil) != test.valid {
			t.Fatalf("decode = %v", err)
		}
	}
}

func TestSharedSDKGoldenAssignments(t *testing.T) {
	data, err := os.ReadFile("testdata/runtime.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	values := map[string]any{
		"prepare":    Prepare{Version: 1, Directory: "/project", Service: "web", Framework: "node", Owner: "0123456789abcdef0123456789abcdef", PID: 123},
		"register":   Registration{Version: 1, RegistrationID: "reg_0123456789abcdef0123456789abcdef", Owner: "0123456789abcdef0123456789abcdef", Target: "http://127.0.0.1:1234"},
		"assignment": Assignment{Version: 1, RegistrationID: "reg_0123456789abcdef0123456789abcdef", Service: "web", Hostname: "web.member.example", PublicURL: "https://web.member.example", Project: projectmeta.PublicMetadata{Namespace: "member.example", Services: map[string]projectmeta.Service{"web": {Namespace: "member.example", Hostname: "web.member.example", URL: "https://web.member.example"}}, Dev: true}},
	}
	for name, value := range values {
		actual, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var expected bytes.Buffer
		if err := json.Compact(&expected, fixtures[name]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, expected.Bytes()) {
			t.Fatalf("%s wire = %s, want %s", name, actual, expected.Bytes())
		}
	}
}

func TestAdHocSocketContractGolden(t *testing.T) {
	data, err := os.ReadFile("testdata/adhoc.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	id, owner := "ivk_0123456789abcdefghijkl", "0123456789abcdef0123456789abcdef"
	values := map[string]any{
		"register": AdHocRegister{Protocol: 1, RegistrationID: id, Owner: owner, PID: 123,
			Target: "http://127.0.0.1:3000", ServerURL: "https://control.example.test",
			Credential: "tnl_eph_test-credential", AllowIP: []string{"198.51.100.9/32"},
			Limits: &AdHocLimits{Requests: 20, Rate: &AdHocRateLimit{Requests: 5, Per: "1m"}, Concurrency: 3}},
		"ready": AdHocStatus{Protocol: 1, RegistrationID: id, State: "routable", PublicURLID: "url_allocated",
			PublicURL: "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test", PublishRunNumber: 1},
		"failed": AdHocStatus{Protocol: 1, RegistrationID: id, State: "failed", FailureCode: "runtime.publication_failed"},
	}
	for name, value := range values {
		actual, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var expected bytes.Buffer
		if err := json.Compact(&expected, fixtures[name]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, expected.Bytes()) {
			t.Fatalf("%s wire shape differs from the shared SDK fixture", name)
		}
	}
}
