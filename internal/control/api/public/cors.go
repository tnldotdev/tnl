package public

import (
	"net/http"

	"github.com/tnldotdev/tnl/internal/serverhttp"
)

func portableCORSRouter(mux *http.ServeMux) *serverhttp.CredentialCORSRouter {
	bearer := serverhttp.CredentialCORSHeaders{Request: []string{"Authorization"}}
	body := serverhttp.CredentialCORSHeaders{Request: []string{"Content-Type"}}
	source := serverhttp.CredentialCORSHeaders{Request: []string{"Authorization", "Content-Type"}}
	create := serverhttp.CredentialCORSHeaders{Request: []string{"Authorization", "Content-Type", "Idempotency-Key"}, Response: []string{"ETag"}}
	read := serverhttp.CredentialCORSHeaders{Request: []string{"Authorization"}, Response: []string{"ETag"}}
	update := serverhttp.CredentialCORSHeaders{Request: []string{"Authorization", "Content-Type", "If-Match"}, Response: []string{"ETag"}}
	remove := serverhttp.CredentialCORSHeaders{Request: []string{"Authorization", "If-Match"}}
	idempotent := serverhttp.CredentialCORSHeaders{Request: []string{"Authorization", "Content-Type", "Idempotency-Key"}}
	// publication and management handlers authenticate explicit tokens or signed
	// body proofs. run-bound browser operations pass their secrets explicitly,
	// never through control cookies. login, credential registration, and private
	// APIs stay absent. discovery returns public facts. CORS does not change any
	// source or grant checks.
	return serverhttp.NewCredentialCORSRouter(mux, map[string]serverhttp.CredentialCORSHeaders{
		"GET /v1/projects/{project_key}/deployments":                                                   bearer,
		"POST /v1/projects/{project_key}/deployments":                                                  create,
		"GET /v1/projects/{project_key}/deployments/{deployment}":                                      read,
		"PATCH /v1/projects/{project_key}/deployments/{deployment}":                                    update,
		"DELETE /v1/projects/{project_key}/deployments/{deployment}":                                   remove,
		"POST /v1/projects/{project_key}/deployments/{deployment}/publisher-enrollments":               idempotent,
		"GET /v1/projects/{project_key}/deployments/{deployment}/publishers":                           bearer,
		"GET /v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}":               bearer,
		"DELETE /v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}":            bearer,
		"POST /v1/projects/{project_key}/deployments/{deployment}/services/{service}/select":           source,
		"POST /v1/visitor-tokens":                                                                      source,
		"POST /v1/services/{service_id}/connector-peer-pairs":                                          source,
		"POST /v1/services/{service_id}/connector-peer-pairs/{pair_id}/renew":                          source,
		"POST /v1/services/{service_id}/connector-peer-pairs/{pair_id}/rebind":                         source,
		"POST /v1/services/{service_id}/connector-peer-pairs/{pair_id}/retire":                         body,
		"GET /v1/projects/{project_key}/deployments/{deployment}/services/{service}/publication":       bearer,
		"POST /v1/projects/{project_key}/deployments/{deployment}/services":                            source,
		"GET /v1/publisher/services/{service_id}":                                                      bearer,
		"DELETE /v1/publisher/services/{service_id}":                                                   bearer,
		"POST /v1/services/{service_id}/runs":                                                          idempotent,
		"POST /v1/services/{service_id}/runs/{service_run_id}/start":                                   source,
		"POST /v1/services/{service_id}/runs/{service_run_id}/renew":                                   source,
		"DELETE /v1/services/{service_id}/runs/{service_run_id}":                                       bearer,
		"POST /v1/services/{service_id}/runs/{service_run_id}/certificate-issuances":                   idempotent,
		"GET /v1/services/{service_id}/runs/{service_run_id}/certificate-issuances/{issuance_id}":      bearer,
		"POST /v1/services/{service_id}/runs/{service_run_id}/certificate-installed":                   source,
		"POST /v1/visitor-policy":                                                                      source,
		"GET /v1/services/{service_id}/runs/{service_run_id}/connector-peer-pairs":                     bearer,
		"POST /v1/services/{service_id}/runs/{service_run_id}/connector-peer-pairs/{pair_id}/delivery": source,
		"POST /v1/services/{service_id}/runs/{service_run_id}/connector-peer-pairs/{pair_id}/prepared": source,
		"POST /v1/services/{service_id}/runs/{service_run_id}/browser/handoff":                         source,
		"POST /v1/services/{service_id}/runs/{service_run_id}/browser/session":                         source,
		"DELETE /v1/services/{service_id}/runs/{service_run_id}/browser/session":                       source,
		"POST /v1/services/{service_id}/runs/{service_run_id}/share-redemptions":                       source,
		"POST /v1/services/{service_id}/runs/{service_run_id}/service-observations":                    source,
		"GET /v1/discovery": {},
	})
}
