package relay

import (
	"net/http"

	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
)

type generatedServer struct {
	handler *handler
}

var _ relayv1.ServerInterface = generatedServer{}

func (s generatedServer) ClaimServicePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	s.handler.claimServicePublisherConnection(w, r, id)
}

func (s generatedServer) ReadyServicePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	s.handler.readyServicePublisherConnection(w, r, id)
}

func (s generatedServer) DisconnectServicePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	s.handler.disconnectServicePublisherConnection(w, r, id)
}

func (s generatedServer) ClaimPublisherConnection(
	response http.ResponseWriter,
	request *http.Request,
	publisherConnectionID relayv1.PublisherConnectionID,
) {
	s.handler.claimPublisherConnection(response, request, publisherConnectionID)
}

func (s generatedServer) DisconnectPublisherConnection(
	response http.ResponseWriter,
	request *http.Request,
	publisherConnectionID relayv1.PublisherConnectionID,
) {
	s.handler.disconnectPublisherConnection(response, request, publisherConnectionID)
}

func (s generatedServer) MarkPublisherConnectionReady(
	response http.ResponseWriter,
	request *http.Request,
	publisherConnectionID relayv1.PublisherConnectionID,
) {
	s.handler.markPublisherConnectionReady(response, request, publisherConnectionID)
}

func (s generatedServer) RegisterRelay(response http.ResponseWriter, request *http.Request) {
	s.handler.registerRelay(response, request)
}

func (s generatedServer) DrainRelay(response http.ResponseWriter, request *http.Request, relayID relayv1.RelayID) {
	s.handler.drainRelay(response, request, relayID)
}

func (s generatedServer) GetRelayTransportCertificate(
	response http.ResponseWriter,
	request *http.Request,
	relayServiceID relayv1.RelayServiceID,
	params relayv1.GetRelayTransportCertificateParams,
) {
	s.handler.getRelayTransportCertificate(response, request, relayServiceID, params)
}

func (s generatedServer) RenewRelay(response http.ResponseWriter, request *http.Request, relayID relayv1.RelayID) {
	s.handler.renewRelay(response, request, relayID)
}
