package diagnostic

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestDefinitionsHaveStableBoundedASCIIOutput(t *testing.T) {
	seenCodes := make(map[Code]bool)
	seenURLs := make(map[string]bool)
	for _, code := range Codes() {
		entry := definitionFor(code)
		if entry.HTTPStatus != 0 && (entry.HTTPStatus < 400 || entry.HTTPStatus > 599) {
			t.Fatalf("invalid HTTP status for %s", code)
		}
		if entry.HTTPStatus == 0 && slices.Contains(entry.Surfaces, "browser") ||
			entry.HTTPStatus != 0 && !slices.Contains(entry.Surfaces, "browser") {
			t.Fatalf("inconsistent browser surface for %s", code)
		}
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

func TestKnownCaseChangesGuidanceButNotDiagnosticIdentity(t *testing.T) {
	err := Wrap(TargetUnavailable, syscall.ECONNREFUSED)
	text, ok := TextForError(err)
	if !ok || !strings.Contains(text, "x  target refused connection") ||
		!strings.Contains(text, "help  https://tnl.dev/e/target?case=connection-refused") ||
		!strings.Contains(text, string(TargetUnavailable)) {
		t.Fatalf("contextual diagnostic = %q", text)
	}
	if got := HelpURL(TargetUnavailable, "connection-refused&token=secret"); got != HelpURL(TargetUnavailable) {
		t.Fatalf("untrusted context = %q", got)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://public.example/", nil)
	request.Header.Set("Accept", "text/html")
	WriteHTTP(response, request, TargetUnavailable, "connection-refused")
	if response.Code != 502 || response.Header().Get("Tnl-Error-Code") != string(TargetUnavailable) ||
		!strings.Contains(response.Body.String(), `href="https://tnl.dev/e/target?case=connection-refused"`) {
		t.Fatalf("browser diagnostic = %d, %q", response.Code, response.Body.String())
	}
}

func TestActionableDiagnosticHelpURLsAreStable(t *testing.T) {
	for code, want := range map[Code]string{
		AuthenticationTimeout: "https://tnl.dev/e/authentication-timeout",
		ServiceAmbiguous:      "https://tnl.dev/e/ambiguous-service",
		PublicURLConflict:     "https://tnl.dev/e/public-url-conflict",
		ProvisioningStalled:   "https://tnl.dev/e/provisioning-stalled",
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
		!strings.Contains(text, "+-- "+string(ProvisioningStalled)+" ") ||
		!strings.HasSuffix(text, "\n\n") {
		t.Fatalf("warning = %q", text)
	}
	output.Reset()
	if err := WritePolicyDenial(&output, "tnl publish", 1, 2); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "+-- "+string(IPPolicyDenied)+" ") ||
		!strings.HasSuffix(got, "\n\n") {
		t.Fatalf("policy denial = %q", got)
	}
}

func TestWriteWarningRejectsShortWrite(t *testing.T) {
	if err := WriteWarning(shortWriter{}, "tnl publish", ProvisioningStalled); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteWarning error = %v", err)
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
		{name: "head plain", method: http.MethodHead, accept: "text/plain", contentType: "text/plain; charset=utf-8", body: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://route.example/", nil)
			request.Header.Set("Accept", test.accept)
			response := httptest.NewRecorder()
			WriteHTTP(response, request, TargetUnavailable)
			if response.Code != http.StatusBadGateway || response.Header().Get("Content-Type") != test.contentType ||
				response.Header().Get("Tnl-Error-Code") != string(TargetUnavailable) ||
				response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Vary") != "Accept" ||
				response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("response = %d, %#v", response.Code, response.Header())
			}
			if test.body != (response.Body.Len() != 0) {
				t.Fatalf("body = %q", response.Body.String())
			}
			get := httptest.NewRecorder()
			getRequest := httptest.NewRequest(http.MethodGet, "https://route.example/", nil)
			getRequest.Header.Set("Accept", test.accept)
			WriteHTTP(get, getRequest, TargetUnavailable)
			if response.Header().Get("Content-Length") != strconv.Itoa(get.Body.Len()) {
				t.Fatalf("Content-Length = %q, GET bytes = %d", response.Header().Get("Content-Length"), get.Body.Len())
			}
			if test.contentType == "text/plain; charset=utf-8" {
				if get.Body.String() != Text(TargetUnavailable) {
					t.Fatalf("plain body = %q", get.Body.String())
				}
				if response.Header().Get("Content-Security-Policy") != "" || response.Header().Get("Referrer-Policy") != "" {
					t.Fatal("plain response has unexpected HTML headers")
				}
			} else {
				if response.Header().Get("Content-Security-Policy") != "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" ||
					response.Header().Get("Referrer-Policy") != "no-referrer" {
					t.Fatalf("HTML headers = %v", response.Header())
				}
				if !strings.Contains(get.Body.String(), `<h1>target unavailable</h1>`) ||
					!strings.Contains(get.Body.String(), `<code>TNL_TARGET_UNAVAILABLE</code>`) ||
					!strings.Contains(get.Body.String(), "<title>target unavailable - tnl</title>") {
					t.Fatalf("HTML diagnostic content = %q", get.Body.String())
				}
			}
			if test.contentType == "text/html; charset=utf-8" && test.body {
				body := response.Body.String()
				if !strings.Contains(body, "<main>") || !strings.Contains(body, `<a href="https://tnl.dev/e/target">`) ||
					!strings.Contains(body, `font-family:"Fira Code"`) {
					t.Fatalf("HTML body = %q", body)
				}
			}
		})
	}
}

type shortWriter struct{}

func (shortWriter) Write(payload []byte) (int, error) { return len(payload) - 1, nil }
