package tnldruntime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIntegrationBinaryStandalonePublish(t *testing.T) {
	fixture := startIntegrationBinaryStandalone(t)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Tnl-Integration", "binary")
		_, _ = io.WriteString(response, request.URL.RequestURI())
	}))
	cleanupIntegrationHTTPServer(t, target, nil)
	publish := startIntegrationBinaryPublish(t, fixture.repositoryRoot, fixture.environment, fixture.tnlPath,
		"--no-config", "publish", target.URL, "--host", "binary.routes.127.0.0.1.nip.io",
		"--allow-ip", "127.0.0.1/32", "--output", "ndjson")
	ready := waitForIntegrationBinaryPublishEvent(t, publish, "ready", 45*time.Second)
	if ready.SchemaVersion != 1 || ready.URL != "https://binary.routes.127.0.0.1.nip.io" || ready.RouteVersion != 1 {
		t.Fatalf("binary ready event = %#v", ready)
	}
	visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
	var response *http.Response
	var body []byte
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		var err error
		response, body, err = visitor.requestURLContext(ctx, http.MethodGet, ready.URL+"/binary?source=integration", nil)
		if err != nil {
			return false, fmt.Errorf("binary visitor: %w\ntnl publish stderr:\n%s\ntnld output:\n%s", err, publish.stderr.String(), fixture.server.output.String())
		}
		return true, nil
	})
	if response.StatusCode != http.StatusOK || string(body) != "/binary?source=integration" || response.Header.Get("X-Tnl-Integration") != "binary" {
		t.Fatalf("binary visitor response = %s, headers %#v, body %q", response.Status, response.Header, body)
	}
	assertIntegrationRouteCertificate(t, response, "binary.routes.127.0.0.1.nip.io")
	stopIntegrationBinaryPublish(t, publish)
	stopped := waitForIntegrationBinaryPublishEvent(t, publish, "stopped", 10*time.Second)
	if stopped.Reason != "canceled" || stopped.TunnelID != ready.TunnelID {
		t.Fatalf("binary stopped event = %#v after ready %#v", stopped, ready)
	}
	waitForIntegrationBinaryPublish(t, publish)
}
