package main

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/0xcadams/tnl/internal/tailbench"
	"tailscale.com/tailcfg"
)

func runSelf(ctx context.Context, listen, token string, region *tailcfg.DERPRegion, maxRoutes int) (tailbench.ClientRunResult, error) {
	server, agent := newAgentServer(listen, token, region, maxRoutes)
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return tailbench.ClientRunResult{}, err
	}
	serverCtx, stopServer := context.WithCancel(ctx)
	serverErr := make(chan error, 1)
	go func() { serverErr <- serveAgentListener(serverCtx, server, agent, listener) }()

	port := listener.Addr().(*net.TCPAddr).Port
	result, runErr := runClient(ctx, token, region, fmt.Sprintf("http://127.0.0.1:%d", port))
	stopServer()
	return result, errors.Join(runErr, <-serverErr)
}
