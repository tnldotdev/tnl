package publisher

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRestrictedBrowserRedirectRequiresTopLevelNavigationAndStopsLoops(t *testing.T) {
	a := &browserAccess{}
	for _, kind := range []string{"navigation", "fetch", "iframe", "post", "loop", "encoded redirect", "websocket"} {
		t.Run(kind, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://web.example.test/settings?tab=profile", nil)
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
			switch kind {
			case "fetch":
				r.Header.Set("Sec-Fetch-Mode", "cors")
			case "iframe":
				r.Header.Set("Sec-Fetch-Dest", "iframe")
			case "post":
				r.Method = http.MethodPost
			case "loop":
				r.AddCookie(&http.Cookie{Name: browserLoginAttemptCookieName, Value: "1"})
			case "encoded redirect":
				r.URL.Path = "//other.test/"
			case "websocket":
				r.Header.Set("Upgrade", "websocket")
			}
			w := httptest.NewRecorder()
			redirected := a.redirectRestricted(w, r)
			if redirected != (kind == "navigation") {
				t.Fatalf("redirected=%t status=%d", redirected, w.Code)
			}
			if redirected {
				cookies := w.Result().Cookies()
				if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" {
					t.Fatal("attempt cookie is not host-bound")
				}
			}
		})
	}
}
