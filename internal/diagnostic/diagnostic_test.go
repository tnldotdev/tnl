package diagnostic

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDefinitionsHaveStableBoundedASCIIOutput(t *testing.T) {
	seenCodes := make(map[Code]bool)
	seenURLs := make(map[string]bool)
	for _, code := range Codes() {
		if seenCodes[code] {
			t.Fatalf("duplicate code %q", code)
		}
		seenCodes[code] = true
		url := HelpURL(code)
		if seenURLs[url] {
			t.Fatalf("duplicate help URL %q", url)
		}
		seenURLs[url] = true
		text := Text(code)
		if !strings.Contains(text, "help  "+url) {
			t.Fatalf("diagnostic %q does not contain its help URL: %q", code, text)
		}
		if !strings.HasPrefix(text, "+--[ tnl ]-- ") || !strings.Contains(text, "+-- "+string(code)+" ") {
			t.Fatalf("diagnostic %q does not contain a framed diagram: %q", code, text)
		}
		for _, line := range strings.Split(text, "\n") {
			if len(line) > 72 {
				t.Fatalf("diagnostic %q line exceeds 72 columns: %q", code, line)
			}
			for _, character := range line {
				if character < 0x20 || character > 0x7e {
					t.Fatalf("diagnostic %q contains non-ASCII output: %q", code, line)
				}
			}
		}
	}
}

func TestActionableDiagnosticHelpURLsAreStable(t *testing.T) {
	for code, want := range map[Code]string{
		FrameworkRegistrationTimeout: "https://tnl.dev/e/framework-registration-timeout",
		TargetMismatch:               "https://tnl.dev/e/target-mismatch",
		AuthenticationTimeout:        "https://tnl.dev/e/authentication-timeout",
		ServiceAmbiguous:             "https://tnl.dev/e/ambiguous-service",
		RouteConflict:                "https://tnl.dev/e/route-conflict",
		ProvisioningStalled:          "https://tnl.dev/e/provisioning-stalled",
	} {
		if got := HelpURL(code); got != want {
			t.Fatalf("HelpURL(%q) = %q, want %q", code, got, want)
		}
	}
}

func TestErrorPreservesCauseAndRendersDetail(t *testing.T) {
	cause := errors.New("dial tcp 127.0.0.1:3000: connection refused")
	err := WrapMessage(TargetUnavailable, "development server did not listen before timeout", cause)
	if !errors.Is(err, cause) {
		t.Fatal("diagnostic error did not preserve its cause")
	}
	if code, ok := CodeOf(err); !ok || code != TargetUnavailable {
		t.Fatalf("CodeOf() = %q, %t", code, ok)
	}
	text, ok := TextForError(err)
	if !ok || !strings.Contains(text, err.Error()) || !strings.Contains(text, "help  "+HelpURL(TargetUnavailable)) ||
		!strings.Contains(text, "+-- "+string(TargetUnavailable)+" ") {
		t.Fatalf("TextForError() = %q, %t", text, ok)
	}
}

func TestWriteWarningUsesDiagnosticFrame(t *testing.T) {
	var output bytes.Buffer
	if err := WriteWarning(&output, "tnl publish", ProvisioningStalled); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.HasPrefix(text, "+--[ tnl publish ]-- provisioning stalled ") ||
		!strings.Contains(text, "help  "+HelpURL(ProvisioningStalled)) ||
		!strings.Contains(text, "+-- "+string(ProvisioningStalled)+" ") {
		t.Fatalf("warning = %q", text)
	}
}

func TestWriteHTTPNegotiatesRepresentation(t *testing.T) {
	for _, test := range []struct {
		name        string
		method      string
		accept      string
		contentType string
		body        bool
	}{
		{name: "browser", method: http.MethodGet, accept: "text/html,application/xhtml+xml", contentType: "text/html; charset=utf-8", body: true},
		{name: "command", method: http.MethodGet, accept: "*/*", contentType: "text/plain; charset=utf-8", body: true},
		{name: "explicit plain", method: http.MethodGet, accept: "text/plain", contentType: "text/plain; charset=utf-8", body: true},
		{name: "html disabled", method: http.MethodGet, accept: "text/html;q=0,*/*;q=1", contentType: "text/plain; charset=utf-8", body: true},
		{name: "head", method: http.MethodHead, accept: "text/html", contentType: "text/html; charset=utf-8", body: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://route.example/", nil)
			request.Header.Set("Accept", test.accept)
			response := httptest.NewRecorder()
			WriteHTTP(response, request, http.StatusBadGateway, TargetUnavailable)
			if response.Code != http.StatusBadGateway || response.Header().Get("Content-Type") != test.contentType ||
				response.Header().Get("Tnl-Error-Code") != string(TargetUnavailable) ||
				response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Vary") != "Accept" ||
				response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("response = %d, %#v", response.Code, response.Header())
			}
			if test.body != (response.Body.Len() != 0) {
				t.Fatalf("body = %q", response.Body.String())
			}
			if test.contentType == "text/html; charset=utf-8" && test.body {
				body := response.Body.String()
				if !strings.Contains(body, "<pre>") || !strings.Contains(body, `<a href="https://tnl.dev/e/target">`) ||
					!strings.Contains(body, `font-family:"Fira Code"`) {
					t.Fatalf("HTML body = %q", body)
				}
			}
		})
	}
}
