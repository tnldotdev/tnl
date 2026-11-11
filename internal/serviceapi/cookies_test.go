package serviceapi

import (
	"net/http"
	"testing"
)

func TestControlCookieTransport(t *testing.T) {
	for origin, local := range map[string]bool{"http://localhost:8445": true, "http://127.0.0.1:8445": true, "https://localhost:8445": false, "https://control.example": false, "http://control.example": false} {
		cookie := ControlCookie(origin, http.Cookie{Name: "__Host-tnl-device", Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		if cookie.Secure == local || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
			t.Fatalf("%s: %+v", origin, cookie)
		}
		name := "__Host-tnl-device"
		if local {
			name = "tnl-device"
		}
		if cookie.Name != name || ControlCookieName(origin, "__Host-tnl-device") != name {
			t.Fatal("cookie name lost its transport scope")
		}
	}
}
