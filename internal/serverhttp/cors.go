package serverhttp

import (
	"net/http"
	"slices"
	"strings"
)

// CredentialCORSHeaders lists the headers needed by one explicitly authenticated
// operation. cookies and other ambient browser credentials must not authorize it.
type CredentialCORSHeaders struct {
	Request  []string
	Response []string
}

// CredentialCORSRouter adds uncredentialed CORS to an exact set of method/path
// patterns. it wraps generated handlers before parameter decoding and handles
// preflight without entering them. register all routes before serving requests.
//
// the wildcard origin deliberately does not support credentials: "include".
// callers must use explicit bearer tokens or authenticated request bodies, never
// cookie authentication, and retain all authorization in the ordinary handlers.
type CredentialCORSRouter struct {
	*http.ServeMux
	routes     map[string]CredentialCORSHeaders
	preflights map[string]map[string]CredentialCORSHeaders
}

func NewCredentialCORSRouter(mux *http.ServeMux, routes map[string]CredentialCORSHeaders) *CredentialCORSRouter {
	return &CredentialCORSRouter{ServeMux: mux, routes: routes, preflights: map[string]map[string]CredentialCORSHeaders{}}
}

func (router *CredentialCORSRouter) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	headers, ok := router.routes[pattern]
	if !ok {
		router.ServeMux.HandleFunc(pattern, handler)
		return
	}
	method, path, _ := strings.Cut(pattern, " ")
	methods, registered := router.preflights[path]
	if !registered {
		methods = map[string]CredentialCORSHeaders{}
		router.preflights[path] = methods
		router.ServeMux.HandleFunc("OPTIONS "+path, credentialPreflight(methods))
	}
	methods[method] = headers
	router.ServeMux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Vary", "Origin")
		if r.Method == method && r.Header.Get("Origin") != "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			if len(headers.Response) != 0 {
				w.Header().Set("Access-Control-Expose-Headers", strings.Join(headers.Response, ", "))
			}
		}
		handler(w, r)
	})
}

func credentialPreflight(methods map[string]CredentialCORSHeaders) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Access-Control-Request-Method")
		w.Header().Add("Vary", "Access-Control-Request-Headers")
		origins, requestedMethods := r.Header.Values("Origin"), r.Header.Values("Access-Control-Request-Method")
		if len(origins) != 1 || origins[0] == "" || len(requestedMethods) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		headers, ok := methods[requestedMethods[0]]
		if !ok || !credentialRequestHeadersAllowed(r.Header.Values("Access-Control-Request-Headers"), headers.Request) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", requestedMethods[0])
		if len(headers.Request) != 0 {
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers.Request, ", "))
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func credentialRequestHeadersAllowed(values, allowed []string) bool {
	for _, value := range values {
		for name := range strings.SplitSeq(value, ",") {
			name = strings.TrimSpace(name)
			if name == "" || !slices.ContainsFunc(allowed, func(allowed string) bool { return strings.EqualFold(name, allowed) }) {
				return false
			}
		}
	}
	return true
}
