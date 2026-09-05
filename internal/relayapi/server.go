package relayapi

import (
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

type generatedServer struct {
	handler *handler
}

var _ relayv1.ServerInterface = generatedServer{}

func (s generatedServer) ClaimPublisherConnection(
	response http.ResponseWriter,
	request *http.Request,
	_ relayv1.PublisherConnectionID,
) {
	s.handler.claimPublisherConnection(response, request)
}

func (s generatedServer) DisconnectPublisherConnection(
	response http.ResponseWriter,
	request *http.Request,
	_ relayv1.PublisherConnectionID,
) {
	s.handler.disconnectPublisherConnection(response, request)
}

func (s generatedServer) MarkPublisherConnectionReady(
	response http.ResponseWriter,
	request *http.Request,
	_ relayv1.PublisherConnectionID,
) {
	s.handler.markPublisherConnectionReady(response, request)
}

func (s generatedServer) RegisterRelay(response http.ResponseWriter, request *http.Request) {
	s.handler.registerRelay(response, request)
}

func (s generatedServer) DrainRelay(response http.ResponseWriter, request *http.Request, _ relayv1.RelayID) {
	s.handler.drainRelay(response, request)
}

func (s generatedServer) GetRelayServiceCertificate(
	response http.ResponseWriter,
	request *http.Request,
	relayServiceID relayv1.RelayServiceID,
	params relayv1.GetRelayServiceCertificateParams,
) {
	s.handler.getRelayServiceCertificate(response, request, relayServiceID, params)
}

func (s generatedServer) RenewRelay(response http.ResponseWriter, request *http.Request, _ relayv1.RelayID) {
	s.handler.renewRelay(response, request)
}
