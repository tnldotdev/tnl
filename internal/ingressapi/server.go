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

func (s generatedServer) DrainIngress(response http.ResponseWriter, request *http.Request, _ ingressv1.IngressID) {
	s.handler.drainIngress(response, request)
}

func (s generatedServer) RenewIngress(response http.ResponseWriter, request *http.Request, _ ingressv1.IngressID) {
	s.handler.renewIngress(response, request)
}

func (s generatedServer) ObserveRouteRecovery(
	response http.ResponseWriter,
	request *http.Request,
	_ ingressv1.IngressID,
	_ int64,
) {
	s.handler.observeRecovery(response, request)
}

func (s generatedServer) GetIngressRoutingTableEvents(
	response http.ResponseWriter,
	request *http.Request,
	_ ingressv1.IngressID,
	_ ingressv1.GetIngressRoutingTableEventsParams,
) {
	s.handler.routingTableEvents(response, request)
}

func (s generatedServer) GetIngressRoutingTableSnapshot(
	response http.ResponseWriter,
	request *http.Request,
	_ ingressv1.IngressID,
	_ ingressv1.GetIngressRoutingTableSnapshotParams,
) {
	s.handler.routingTableSnapshot(response, request)
}

func (s generatedServer) ReportIngressUsage(response http.ResponseWriter, request *http.Request, _ ingressv1.IngressID) {
	s.handler.reportUsage(response, request)
}
