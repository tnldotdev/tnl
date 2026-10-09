package diagnostic

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestRestrictedBrowserActionKeepsDiagnosticAndStyle(t *testing.T) {
	for _, post := range []bool{false, true} {
		request := httptest.NewRequest(http.MethodGet, "https://app.example/settings", nil)
		request.Header.Set("Accept", "text/html")
		response := httptest.NewRecorder()
		WriteRestrictedBrowserHTTP(response, request, SecondaryAction{Label: "sign in <safely>", Path: "/__tnl/team/login?return=%2Fsettings&prompt=select_account", Post: post})
		body := response.Body.String()
		if response.Code != http.StatusForbidden || response.Header().Get("Tnl-Error-Code") != string(IPPolicyDenied) || response.Header().Get("Location") != "" || response.Header().Get("Content-Length") != strconv.Itoa(len(body)) || response.Header().Get("Content-Type") != "text/html; charset=utf-8" || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("restricted diagnostic = %d %#v", response.Code, response.Header())
		}
		for _, want := range []string{"this public url is restricted", `font-family:"Fira Code"`, `<code>TNL_IP_POLICY_DENIED</code>`, HelpURL(IPPolicyDenied), `class="secondary"`, "sign in &lt;safely&gt;", "&amp;prompt=select_account"} {
			if !strings.Contains(body, want) {
				t.Fatalf("restricted diagnostic missing %q: %s", want, body)
			}
		}
		if strings.Contains(body, "<script") || strings.Contains(body, "http-equiv") {
			t.Fatal("restricted diagnostic automatically navigates")
		}
		if post {
			if !strings.Contains(body, `method="post"`) || !strings.Contains(response.Header().Get("Content-Security-Policy"), "form-action 'self'") || response.Header().Get("Referrer-Policy") != "same-origin" {
				t.Fatal("account-switch form cannot submit safely")
			}
		} else if strings.Contains(body, "<form") || response.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("sign-in action changed diagnostic form or referrer policy")
		}
	}
}

func TestBrowserActionsOnlyAppearOnHTMLDocumentGET(t *testing.T) {
	for _, test := range []struct {
		name, method, accept, dest, mode string
		document                         bool
	}{
		{name: "legacy navigation", method: "GET", accept: "text/html", document: true},
		{name: "navigation", method: "GET", accept: "text/html,*/*;q=.8", dest: "document", mode: "navigate", document: true},
		{name: "API", method: "GET", accept: "application/json"},
		{name: "script", method: "GET", accept: "text/html", dest: "script", mode: "no-cors"},
		{name: "fetch", method: "GET", accept: "text/html", mode: "cors"},
		{name: "same-origin fetch", method: "GET", accept: "text/html", mode: "same-origin"},
		{name: "iframe", method: "GET", accept: "text/html", dest: "iframe", mode: "navigate"},
		{name: "unknown destination", method: "GET", accept: "text/html", dest: "unknown", mode: "navigate"},
		{name: "HTML refused", method: "GET", accept: "text/html;q=0,*/*"},
		{name: "POST", method: "POST", accept: "text/html", dest: "document", mode: "navigate"},
		{name: "HEAD", method: "HEAD", accept: "text/html", dest: "document", mode: "navigate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://app.example/", nil)
			request.Header.Set("Accept", test.accept)
			request.Header.Set("Sec-Fetch-Dest", test.dest)
			request.Header.Set("Sec-Fetch-Mode", test.mode)
			if IsHTMLDocumentRequest(request) != test.document {
				t.Fatal("incorrect document classification")
			}
			response := httptest.NewRecorder()
			WriteRestrictedBrowserHTTP(response, request, SecondaryAction{Label: "sign in", Path: "/__tnl/team/login"})
			if strings.Contains(response.Body.String(), `class="secondary"`) != test.document || response.Header().Get("Location") != "" {
				t.Fatalf("document action = %d %s", response.Code, response.Body.String())
			}
			if !test.document {
				original := httptest.NewRecorder()
				WriteHTTP(original, request, IPPolicyDenied)
				if response.Body.String() != original.Body.String() || response.Code != original.Code {
					t.Fatal("non-document diagnostic changed")
				}
			}
		})
	}
}
