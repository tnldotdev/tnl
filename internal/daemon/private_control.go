package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlrelay "github.com/tnldotdev/tnl/internal/control/api/private/relay"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
)

type privateControlSettings struct {
	ingressLeaseDuration time.Duration
	relayLeaseDuration   time.Duration
	listen               string
	listener             net.Listener
}

func privateControlSettingsFrom(cfg daemonconfig.Config) privateControlSettings {
	return privateControlSettings{
		ingressLeaseDuration: cfg.IngressLeaseDuration,
		relayLeaseDuration:   cfg.RelayLeaseDuration,
		listen:               cfg.PrivateControlListen,
	}
}

func (d *daemon) startPrivateControlAPIs(_ context.Context, settings privateControlSettings, metrics *observability.Metrics) error {
	ingressHandler, err := controlingress.NewHandler(controlingress.Config{
		Store: d.database, ClusterSecrets: d.clusterSecrets,
		LeaseDuration: settings.ingressLeaseDuration,
	})
	if err != nil {
		return err
	}
	relayHandler, err := controlrelay.NewHandler(controlrelay.Config{
		Store: d.database, ClusterSecrets: d.clusterSecrets,
		LeaseDuration: settings.relayLeaseDuration,
	})
	if err != nil {
		return err
	}
	handler := privateControlHandler(ingressHandler, relayHandler, metrics)
	listener := settings.listener
	if listener == nil {
		listener, err = net.Listen("tcp", settings.listen)
		if err != nil {
			return fmt.Errorf("listen for private control API: %w", err)
		}
	}
	d.privateControlListener = listener
	d.privateControlServer = controlHTTPServer(handler, d.controlTLS)
	d.start("serve private control API", func() error { return serveTLS(d.privateControlServer, listener) })
	log.Printf("private control API listening on %s", listener.Addr())
	return nil
}

type privateAPIHandler interface {
	http.Handler
	MatchedPattern(*http.Request) string
}

func privateControlHandler(ingressHandler, relayHandler privateAPIHandler, metrics *observability.Metrics) http.Handler {
	ingressObserved := metrics.APIRequests("private_ingress", ingressHandler)
	relayObserved := metrics.APIRequests("private_relay", relayHandler)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		switch {
		case matchedAPIPattern(request, ingressHandler.MatchedPattern) != "":
			request.Pattern = ingressHandler.MatchedPattern(request)
			ingressObserved.ServeHTTP(response, request)
		case matchedAPIPattern(request, relayHandler.MatchedPattern) != "":
			request.Pattern = relayHandler.MatchedPattern(request)
			relayObserved.ServeHTTP(response, request)
		default:
			serviceapi.WriteProblem(response, http.StatusNotFound, "not_found", "Private control endpoint not found", "")
		}
	})
}
