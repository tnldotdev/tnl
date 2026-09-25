// Package httpclient contains shared HTTP client policy for internal clients.
package httpclient

import "net/http"

// NoRedirects returns a shallow clone of client that returns redirect responses
// to its caller. A nil client uses the standard zero-value configuration.
func NoRedirects(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}
