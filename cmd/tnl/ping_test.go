package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
)

func TestPingDoesNotLoadProjectOrSendCredentials(t *testing.T) {
	if _, err := commandForTest(&cli{}, io.Discard)([]string{"ping", "https://example.com", "--protocol", "http"}); err == nil {
		t.Fatal("ping still accepts a redundant protocol override")
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("visitor probe sent credentials")
		}
		output.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var output, diagnostics bytes.Buffer
	if err := run(t.Context(), []string{"--config", "missing.yml", "ping", server.URL, "--output", "json"}, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var result publisherapp.PingResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.State != "responding" || result.Status != http.StatusNoContent || requests != 1 {
		t.Fatalf("ping result=%s, requests=%d, err=%v", output.String(), requests, err)
	}
}

func TestPingReportsHTTPResultAndExitsZeroOnAppErrors(t *testing.T) {
	for _, tt := range []struct {
		status int
		code   string
		want   string
	}{
		{200, "", "HTTP 200 OK"},
		{302, "", "HTTP 302 Found (redirect not followed)"},
		{304, "", "HTTP 304 Not Modified"},
		{404, "", "HTTP 404 Not Found"},
		{500, "", "HTTP 500 Internal Server Error"},
		{599, "", "HTTP 599"},
		{403, "TNL_IP_POLICY_DENIED", "HTTP 403 Forbidden (tnl: TNL_IP_POLICY_DENIED)"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(publisherapp.DiagnosticHeader, tt.code)
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			var out bytes.Buffer
			flags := pingCommand{URL: server.URL, Output: statusOutputHuman}
			err := runPing(t.Context(), flags, &out)
			if (err != nil) != (tt.code != "") || out.String() != tt.want+"  "+server.URL+"\n" {
				t.Fatalf("ping = %q, %v", &out, err)
			}
			if err != nil {
				var diag bytes.Buffer
				writeCommandError(&diag, err)
				if !strings.Contains(diag.String(), "IP address") || !strings.Contains(diag.String(), "TNL_CLIENT_TUNNEL_UNAVAILABLE") {
					t.Fatalf("ping denial = %q", &diag)
				}
			}
			if tt.status == http.StatusNotModified {
				flags.Output = statusOutputJSON
				out.Reset()
				if err := runPing(t.Context(), flags, &out); err != nil || !strings.Contains(out.String(), `"state":"redirected (not followed)"`) {
					t.Fatalf("304 machine result = %q, %v", &out, err)
				}
			}
		})
	}
}

func TestPingConnectionFailureExplainsTheVisitorCheck(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	var out, diag bytes.Buffer
	err := runPing(t.Context(), pingCommand{URL: server.URL}, &out)
	if err == nil || out.String() != "No HTTP response  "+server.URL+"\n" {
		t.Fatalf("ping = %q, %v", &out, err)
	}
	writeCommandError(&diag, err)
	if !strings.Contains(diag.String(), "connection or TLS verification failed") {
		t.Fatalf("ping error = %q", &diag)
	}
}

func TestPingInvalidURLShowsExpectedInput(t *testing.T) {
	var out, diag bytes.Buffer
	err := runPing(t.Context(), pingCommand{URL: "app"}, &out)
	if err == nil || out.Len() != 0 {
		t.Fatalf("ping = %q, %v", &out, err)
	}
	writeCommandError(&diag, err)
	if !strings.Contains(diag.String(), "provide a full HTTP or HTTPS URL") || !strings.Contains(diag.String(), "TNL_CLIENT_INVALID_COMMAND") {
		t.Fatalf("ping error = %q", &diag)
	}
}
