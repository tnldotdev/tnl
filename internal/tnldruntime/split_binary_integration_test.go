package tnldruntime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIntegrationBinarySplitPublishAndVisit(t *testing.T) {
	f := startIntegrationBinarySplit(t)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(response, request.URL.RequestURI())
	}))
	cleanupIntegrationHTTPServer(t, target, nil)
	publish := startIntegrationBinaryPublish(t, f.repositoryRoot, f.environment, f.tnlPath,
		"--no-config", "publish", target.URL, "--host", f.routeHost, "--allow-all-ips", "--output", "ndjson")
	ready := waitForIntegrationBinaryPublishEvent(t, publish, "ready", 45*time.Second)
	if ready.URL != "https://"+f.routeHost || ready.RouteVersion != 1 {
		t.Fatalf("split binary ready event = %#v", ready)
	}
	waitForIngressRoutingCurrent(t, inspectStandaloneTestDatabase(t, f.databaseURL), 1)
	visitor := newIntegrationVisitor(t, f.pebble.roots, "")
	response, body, err := visitor.requestURL(http.MethodGet, ready.URL+"/split?source=binary", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "/split?source=binary" {
		t.Fatalf("split binary visitor response = %s, %q", response.Status, body)
	}
	assertIntegrationRouteCertificate(t, response, f.routeHost)
	stopIntegrationBinaryPublish(t, publish)
	waitForIntegrationBinaryPublish(t, publish)
}
