package main

import (
	"context"
	"errors"
	"io"
	"net/url"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type authBrowserCommand struct {
	remoteFlags `embed:""`
	URL         string `arg:"" name:"url" required:"" help:"Public HTTP service name, service ID, hostname, host:port, or HTTPS URL to open."`
}

func runAuthBrowser(ctx context.Context, flags authBrowserCommand, output, diagnostics io.Writer) error {
	s, err := openTeamSession(ctx, flags.remoteFlags, "tnl auth browser", diagnostics)
	if err != nil {
		return err
	}
	defer s.Close()
	item, err := resolveVisitorService(ctx, s, flags.URL)
	if err != nil {
		return err
	}
	if item.Protocol != "http" {
		return failure.Wrap("select an HTTP public URL", failure.InvalidCommand, errors.New("browser handoff requires an HTTP public URL"))
	}
	saved, found, err := s.Store().ControlSession(ctx)
	if err != nil {
		return err
	}
	if !found {
		return failure.Wrap("select saved CLI session", failure.Authentication, errors.New("sign in with tnl auth login before creating a browser handoff"))
	}
	authority, err := clientauthority.New(s.Authenticated().ServerEndpoint, nil, credentials.AccessToken(saved.AccessToken))
	if err != nil {
		return err
	}
	handoff, err := authority.IssueControlBrowserHandoff(ctx, item.Id, credentials.RefreshToken(saved.RefreshToken))
	if err != nil {
		return err
	}
	parsed, err := url.Parse(handoff)
	if err != nil || parsed.Scheme != "https" || parsed.Host != item.Endpoint.Hostname || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return failure.Wrap("validate browser handoff", failure.ServerResponseInvalid, errors.New("invalid browser handoff response"))
	}
	if err = openBrowser(handoff); err != nil {
		return failure.Wrap("open browser handoff", failure.BrowserOpenFailed, err)
	}
	return writeResult(output,
		clioutput.Line("https://"+item.Endpoint.Hostname),
		clioutput.Text("Opened in your browser. Revoking this CLI session also ends browser access."))
}
