package controlapi

import (
	"fmt"
	"net/http"

	"github.com/tnldotdev/tnl/internal/webhookcatalog"
	"github.com/tnldotdev/tnl/internal/webhookprovider"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) GetWebhookProviderSource(response http.ResponseWriter, request *http.Request, provider controlv1.WebhookProvider) {
	name := string(provider)
	if !webhookprovider.Valid(name) {
		h.config.Metrics.ObserveWebhookProviderSource(name, "unknown")
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "webhook provider not found")
		return
	}
	result, err := h.webhookCatalog.Read(request.Context(), name)
	if err != nil {
		h.config.Metrics.ObserveWebhookProviderSource(name, "unavailable")
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "webhook provider source unavailable")
		return
	}
	response.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", result.MaxAge))
	response.Header().Set("ETag", result.ETag)
	if request.Header.Get("If-None-Match") == result.ETag {
		h.config.Metrics.ObserveWebhookProviderSource(name, "not_modified")
		response.WriteHeader(http.StatusNotModified)
		return
	}
	h.config.Metrics.ObserveWebhookProviderSource(name, "served")
	writeJSON(response, http.StatusOK, struct {
		Source webhookcatalog.Source `json:"source"`
	}{Source: result.Source})
}
