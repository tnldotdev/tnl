package ingressapi

import (
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type generatedServer struct {
	handler *handler
}

var _ ingressv1.ServerInterface = generatedServer{}

func (s generatedServer) RegisterIngress(response http.ResponseWriter, request *http.Request) {
	s.handler.registerIngress(response, request)
}

func (s generatedServer) DrainIngress(response http.ResponseWriter, request *http.Request, ingressID ingressv1.IngressID) {
	s.handler.drainIngress(response, request, ingressID)
}

func (s generatedServer) RenewIngress(response http.ResponseWriter, request *http.Request, ingressID ingressv1.IngressID) {
	s.handler.renewIngress(response, request, ingressID)
}

func (s generatedServer) ObservePublicURLRecovery(
	response http.ResponseWriter,
	request *http.Request,
	ingressID ingressv1.IngressID,
	recoveryEpisodeID int64,
) {
	s.handler.observeRecovery(response, request, ingressID, recoveryEpisodeID)
}

func (s generatedServer) GetIngressRoutingTableEvents(
	response http.ResponseWriter,
	request *http.Request,
	ingressID ingressv1.IngressID,
	params ingressv1.GetIngressRoutingTableEventsParams,
) {
	s.handler.routingTableEvents(response, request, ingressID, params)
}

func (s generatedServer) GetIngressRoutingTableSnapshot(
	response http.ResponseWriter,
	request *http.Request,
	ingressID ingressv1.IngressID,
	params ingressv1.GetIngressRoutingTableSnapshotParams,
) {
	s.handler.routingTableSnapshot(response, request, ingressID, params)
}

func (s generatedServer) ReportIngressUsage(response http.ResponseWriter, request *http.Request, ingressID ingressv1.IngressID) {
	s.handler.reportUsage(response, request, ingressID)
}
