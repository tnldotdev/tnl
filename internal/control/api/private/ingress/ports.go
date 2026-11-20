package ingress

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type portInventoryStore interface {
	ReadIngressServicePorts(context.Context, string) ([]tcpport.Range, error)
}

func (s generatedServer) GetIngressPoolPorts(w http.ResponseWriter, r *http.Request, pool string) {
	if !serverhttp.ValidIdentifiers(pool) {
		serverhttp.WriteProblem(w, http.StatusBadRequest, "invalid_request", "Ingress pool identifier is invalid", "")
		return
	}
	ranges, err := s.handler.service.store.ReadIngressServicePorts(r.Context(), pool)
	if s.handler.writeServiceError(w, r, err) {
		return
	}
	result := make([]ingressv1.ServicePortRange, len(ranges))
	for i, value := range ranges {
		result[i] = ingressv1.ServicePortRange{First: value.First, Last: value.Last}
	}
	serverhttp.WriteJSON(w, http.StatusOK, result)
}
