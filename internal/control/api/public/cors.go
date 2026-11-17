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
	enroll := serverhttp.CredentialCORSHeaders{Request: []string{"Authorization", "Content-Type", "Idempotency-Key"}}
	// these operations authenticate explicit tokens or signed body proofs only.
	// browser login, credential registration, publication, and private APIs are
	// deliberately absent. CORS does not change any source or grant checks.
	return serverhttp.NewCredentialCORSRouter(mux, map[string]serverhttp.CredentialCORSHeaders{
		"GET /v1/projects/{project_key}/deployments":                                         bearer,
		"POST /v1/projects/{project_key}/deployments":                                        create,
		"GET /v1/projects/{project_key}/deployments/{deployment}":                            read,
		"PATCH /v1/projects/{project_key}/deployments/{deployment}":                          update,
		"DELETE /v1/projects/{project_key}/deployments/{deployment}":                         remove,
		"POST /v1/projects/{project_key}/deployments/{deployment}/publisher-enrollments":     enroll,
		"GET /v1/projects/{project_key}/deployments/{deployment}/publishers":                 bearer,
		"GET /v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}":     bearer,
		"DELETE /v1/projects/{project_key}/deployments/{deployment}/publishers/{publisher}":  bearer,
		"POST /v1/projects/{project_key}/deployments/{deployment}/services/{service}/select": source,
		"POST /v1/visitor-tokens":                                                            source,
		"POST /v1/services/{service_id}/connector-peer-pairs":                                source,
		"POST /v1/services/{service_id}/connector-peer-pairs/{pair_id}/renew":                source,
		"POST /v1/services/{service_id}/connector-peer-pairs/{pair_id}/rebind":               source,
		"POST /v1/services/{service_id}/connector-peer-pairs/{pair_id}/retire":               body,
	})
}
