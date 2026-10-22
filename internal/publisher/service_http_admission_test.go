package publisher_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func TestServiceHTTPAdmissionPreservesApplicationAuthWithoutClientCertificate(t *testing.T) {
	certificates := serviceCertificates(t)
	const hostname = "web.production.storefront.example.test"
	var captured atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 0 || !slices.Equal(r.Header.Values("Authorization"), []string{"caller-one", "caller-two"}) || r.Header.Get("X-App") != "kept" {
			t.Error("application auth or independent TLS boundary failed")
		}
		captured.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	var allowed atomic.Bool
	server := publisher.ServiceStream{Protocol: config.ProtocolHTTP, Hostname: hostname, Target: strings.TrimPrefix(upstream.URL, "https://"), TargetTLS: upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), TLS: &tls.Config{Certificates: []tls.Certificate{certificates.server}}, Visitor: publisher.ConnectorVisitor{Check: func(context.Context) (publisher.ServiceVisitorDecision, error) {
		return publisher.ServiceVisitorDecision{Allowed: allowed.Load(), ValidUntil: time.Now().Add(time.Minute)}, nil
	}}}
	server.TargetTLS.ServerName = "127.0.0.1"
	address := managedPublisherListener(t, server)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certificates.roots, ServerName: hostname}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("https://" + address + "/v1/models")
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil && response.StatusCode < 400 {
		t.Fatal("unauthorized visitor succeeded")
	}
	if captured.Load() != 0 {
		t.Fatal("unauthorized visitor caused a target request")
	}
	allowed.Store(true)
	request, _ := http.NewRequestWithContext(t.Context(), "POST", "https://"+address+"/v1/models", strings.NewReader("streamed application data"))
	request.Header["Authorization"] = []string{"caller-one", "caller-two"}
	request.Header.Set("X-App", "kept")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal("authorized visitor did not reach verified target")
	}
	_ = response.Body.Close()
	if response.StatusCode != 204 || captured.Load() != 1 {
		t.Fatal("authenticated target forwarding failed")
	}
}
