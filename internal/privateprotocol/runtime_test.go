package privateprotocol

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictRequestBounds(t *testing.T) {
	golden := `{"version":1,"directory":"/project","service":"web","framework":"node","owner":"0123456789abcdef0123456789abcdef","pid":123}`
	for _, test := range []struct {
		body, origin string
		valid        bool
	}{{golden, "", true}, {golden + " {}", "", false}, {strings.Replace(golden, `"pid":123`, `"pid":123,"credential":"old-bearer"`, 1), "", false}, {golden, "https://app.example", false}, {strings.Repeat("x", MaxBytes+1), "", false}} {
		r := httptest.NewRequest("POST", "/v1/prepare", strings.NewReader(test.body))
		r.Header.Set("Content-Type", "application/json")
		if test.origin != "" {
			r.Header.Set("Origin", test.origin)
		}
		var value Prepare
		if err := Decode(httptest.NewRecorder(), r, &value); (err == nil) != test.valid {
			t.Fatalf("decode = %v", err)
		}
	}
}

func TestCapabilitiesRejectOriginsAuthoritiesAndReplacementOwners(t *testing.T) {
	var capabilities *Capabilities
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capabilities.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { Write(w, 200, Grant(r)) })).ServeHTTP(w, r)
	}))
	defer server.Close()
	var err error
	capabilities, err = NewCapabilities(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	owner := capabilities.Owner()
	for _, test := range []struct {
		host, origin, secret string
		status               int
	}{{"", "", owner.Capability, 200}, {"localhost:1234", "", owner.Capability, 401}, {"", "https://app.example", owner.Capability, 401}, {"", "", strings.Repeat("0", 64), 401}} {
		request, _ := http.NewRequest("GET", server.URL+"/v1/health", nil)
		request.Header.Set("Authorization", "Bearer "+test.secret)
		if test.host != "" {
			request.Host = test.host
		}
		if test.origin != "" {
			request.Header.Set("Origin", test.origin)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != test.status {
			t.Fatalf("status=%d want=%d", response.StatusCode, test.status)
		}
	}
	name := "web"
	app, err := capabilities.Issue(CapabilityRequest{Scope: "app", Service: &name})
	if err != nil || app.Scope != "app" || app.Capability == owner.Capability {
		t.Fatalf("app=%v err=%v", app.Scope, err)
	}
	next, err := NewCapabilities(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	capabilities = next
	if err := Call(t.Context(), app, "GET", "/v1/health", nil, nil); err != ErrUnauthorized {
		t.Fatalf("replaced owner accepted capability: %v", err)
	}
}

func TestDescriptorsArePrivateAndAtomic(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	path, err := DescriptorPath(root, "/project")
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := NewCapabilities("http://127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	owner := capabilities.Owner()
	if err := WriteEndpoint(path, owner); err != nil {
		t.Fatal(err)
	}
	if value, err := ReadEndpoint(path); err != nil || value.OwnerId != owner.OwnerId {
		t.Fatalf("descriptor=%v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEndpoint(path); err == nil {
		t.Fatal("read public descriptor")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	next, _ := NewCapabilities(owner.Url)
	if err := WriteEndpoint(path, next.Owner()); err != nil {
		t.Fatal(err)
	}
	RemoveEndpoint(path, owner.OwnerId)
	if _, err := ReadEndpoint(path); err != nil {
		t.Fatal("old owner removed replacement descriptor")
	}
	link := filepath.Join(filepath.Dir(path), "symlink.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadEndpoint(link); err == nil {
		t.Fatal("read symlink descriptor")
	}
	encoded, _ := json.Marshal(next.Owner())
	if strings.Contains(string(encoded), "socket") {
		t.Fatal("descriptor contains retired transport")
	}
}
