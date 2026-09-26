package tnldruntime

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBinaryIntegrationSplitPublishAndVisit(t *testing.T) {
	f := startIntegrationBinarySplit(t)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(response, request.URL.RequestURI())
	}))
	cleanupIntegrationHTTPServer(t, target, nil)
	publish := startIntegrationBinaryPublish(t, f.repositoryRoot, f.environment, f.tnlPath,
		"--no-config", "publish", target.URL, "--host", f.publicURLHost, "--allow-all-ips", "--output", "ndjson")
	ready := waitForIntegrationBinaryPublishEvent(t, publish, "ready", 45*time.Second)
	if ready.URL != "https://"+f.publicURLHost || ready.PublishRunNumber != 1 {
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
	assertIntegrationPublicURLCertificate(t, response, f.publicURLHost)
	stopIntegrationBinaryPublish(t, publish)
	waitForIntegrationBinaryPublish(t, publish)
}
