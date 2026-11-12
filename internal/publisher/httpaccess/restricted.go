package httpaccess

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

const LoginAttemptCookieName = "__Host-tnl-browser-attempt"

func markBrowserLoginAttempt(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: LoginAttemptCookieName, Value: "1", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(5 * time.Minute)})
}

// redirectRestricted starts sign-in only for an actual top-level navigation.
// the short-lived host cookie prevents repeated OIDC/return loops after denial.
func (a *Browser) RedirectRestricted(w http.ResponseWriter, r *http.Request, loginAvailable bool) bool {
	if r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
		return false
	}
	for key := range r.Header {
		if strings.EqualFold(key, VisitorTokenHeader) || strings.EqualFold(key, ShareHeaderName) || strings.EqualFold(key, "Tnl-Access-Token") {
			return false
		}
	}
	if a == nil || r.Method != http.MethodGet || r.Header.Get("Sec-Fetch-Mode") != "navigate" || r.Header.Get("Sec-Fetch-Dest") != "document" || r.Header.Get("Upgrade") != "" || !validBrowserPath(r.URL.RequestURI()) {
		return false
	}
	if a.Tokens != nil && r.Header.Get(VisitorTokenHeader) == "" && (SuppliedCookieCount(r, ShareCookieName) > 0 || SuppliedCookieCount(r, BrowserCookieName) > 0) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, "/__tnl/team/renew?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return true
	}
	if !loginAvailable {
		return false
	}
	if _, err := r.Cookie(LoginAttemptCookieName); err == nil {
		return false
	}
	markBrowserLoginAttempt(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "/__tnl/team/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
	return true
}
