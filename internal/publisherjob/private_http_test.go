package publisherjob

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrivateHTTPSOriginDoesNotNegotiateTargetTLS(t *testing.T) {
	// even an HTTPS descriptor cannot insert a publisher-side handshake.
	// private bytes are owned by the connecting client.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Host+" "+r.URL.Path) }))
	defer target.Close()
	address, close, err := PrivateTarget(t.Context(), PrivateTargetPlan{Protocol: "http", Target: strings.Replace(target.URL, "http://", "https://", 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+address+"/unchanged", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "private-client.example"
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "private-client.example /unchanged" {
		t.Fatalf("private bytes changed: %q %v", body, err)
	}
}

func TestPrivateClientOwnsNativeHTTPS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "client TLS") }))
	defer target.Close()
	address, close, err := PrivateTarget(t.Context(), PrivateTargetPlan{Protocol: "http", Target: target.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	response, err := target.Client().Get("https://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "client TLS" {
		t.Fatalf("client TLS was changed: %q %v", body, err)
	}
	job := Job{Kind: KindPrivateService, Protocol: "http", Target: target.URL, TargetTLSName: "unexpected"}
	if err := validateTarget(&job); err == nil {
		t.Fatal("private publication accepted publisher-side target TLS")
	}
}
