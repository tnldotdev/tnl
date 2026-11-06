package acquisition

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
)

// the endpoint is fixed; neither project configuration nor environment may send
// identity requests elsewhere. bypass proxies and refuse redirects.
func googleAssertion(ctx context.Context, audience string, transport http.RoundTripper) (string, error) {
	if !config.ExactWorkloadValue(audience) {
		return "", ErrAssertionUnavailable
	}
	if transport == nil {
		local := http.DefaultTransport.(*http.Transport).Clone()
		local.Proxy = nil
		transport = local
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience="+url.QueryEscape(audience)+"&format=full", nil)
	if err != nil {
		return "", ErrAssertionUnavailable
	}
	request.Header.Set("Metadata-Flavor", "Google")
	response, err := client.Do(request)
	if err != nil {
		return "", ErrAssertionUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Metadata-Flavor") != "Google" {
		return "", ErrAssertionUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	if err != nil || len(data) > 32<<10 {
		return "", ErrAssertionUnavailable
	}
	return boundedAssertion(string(data))
}
