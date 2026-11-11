package serviceapi

import (
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming"
)

// ControlCookieName keeps production host-prefix guarantees separate from local HTTP.
func ControlCookieName(origin, name string) string {
	if naming.IsLoopbackHTTP(origin) {
		return strings.TrimPrefix(name, "__Host-")
	}
	return name
}

func ControlCookie(origin string, cookie http.Cookie) *http.Cookie {
	cookie.Name = ControlCookieName(origin, cookie.Name)
	cookie.Secure = !naming.IsLoopbackHTTP(origin)
	return &cookie
}
