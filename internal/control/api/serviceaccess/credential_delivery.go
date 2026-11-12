package serviceaccess

import (
	"errors"
	"net/http"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	failureproblem "github.com/tnldotdev/tnl/internal/failure/problem"
	"github.com/tnldotdev/tnl/internal/httpjson"
)

// write the secretless result of an exact retry.
func WriteCredentialDeliveryProblem(response http.ResponseWriter, err error) bool {
	var delivery *controlstate.CredentialDeliveryUnavailable
	if !errors.As(err, &delivery) {
		return false
	}
	code := "credential_delivery_unavailable"
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Link", "<"+failureproblem.HelpURL(code, "")+">; rel=\"help\"")
	httpjson.WriteProblem(response, http.StatusConflict, failureproblem.Problem{
		Type: failureproblem.URL(code), Title: "credential delivery unavailable", Status: http.StatusConflict,
		Code: code, Detail: "Control retains only a digest. Revoke the resource in details.resource_id and create with a new idempotency key if delivery was lost.",
		RequestID: failureproblem.NewRequestID(), Details: map[string]any{"resource_id": delivery.ResourceID},
	})
	return true
}
