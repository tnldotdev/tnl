package main

import (
	"context"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func authenticatePublisher(ctx context.Context, state *clientstate.Database, serverURL, accessToken, command string, stdin io.Reader, diagnostics io.Writer) (*auth.Client, error) {
	return auth.Authenticate(ctx, auth.Config{ServerEndpoint: serverURL, State: state, AccessToken: accessToken, Diagnostics: diagnostics, OpenURL: interactiveBrowserOpener(stdin), AuthenticationPrompt: authenticationPrompt(diagnostics, command)})
}

func projectAuthentication(ctx context.Context, state *clientstate.Database, server, command string, input io.Reader, diagnostics io.Writer) (*auth.Client, error) {
	return authenticatePublisher(ctx, state, server, "", command, input, diagnostics)
}

func (flags tunnelFlags) limits() publisher.ApplicationLimits {
	limits := publisher.ApplicationLimits{}
	if flags.Requests != nil {
		limits.Requests = *flags.Requests
	}
	if flags.Concurrency != nil {
		limits.Concurrency = *flags.Concurrency
	}
	if flags.RateRequests != nil {
		limits.RateRequests = *flags.RateRequests
		limits.RatePer, _ = time.ParseDuration(flags.RatePer)
	}
	if flags.RateBurst != nil {
		limits.RateBurst = *flags.RateBurst
	}
	return limits
}
