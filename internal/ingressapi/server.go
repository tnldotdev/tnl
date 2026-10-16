package ingressapi

import (
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type generatedServer struct {
	handler *handler
}

var _ ingressv1.ServerInterface = generatedServer{}

func (s generatedServer) ClaimPrivateConnectorSession(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	s.handler.claimPrivateConnectorSession(w, r, id)
}

func (s generatedServer) ClaimPrivateServiceTicket(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	s.handler.claimPrivateServiceTicket(w, r, id)
}

func (s generatedServer) RecheckPrivateServiceVisitor(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	s.handler.recheckPrivateServiceVisitor(w, r, id)
}

func (s generatedServer) GetPrivateServiceSnapshot(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID, p ingressv1.GetPrivateServiceSnapshotParams) {
	s.handler.privateServiceSnapshot(w, r, id, p)
}

func (s generatedServer) GetPrivateServiceEvents(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID, p ingressv1.GetPrivateServiceEventsParams) {
	s.handler.privateServiceEvents(w, r, id, p)
}

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
