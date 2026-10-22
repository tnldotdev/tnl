package main

import (
	"context"
	"errors"
	"io"
	"net/url"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
)

type authBrowserCommand struct {
	remoteFlags `embed:""`
	URL         string `arg:"" name:"url" required:"" help:"HTTP public URL ID or hostname to open with your current control session."`
}

func runAuthBrowser(ctx context.Context, flags authBrowserCommand, output, diagnostics io.Writer) error {
	s, err := openTeamSession(ctx, flags.remoteFlags, "tnl auth browser", diagnostics)
	if err != nil {
		return err
	}
	defer s.Close()
	item, err := resolveVisitorPublicURL(ctx, s, flags.URL)
	if err != nil {
		return err
	}
	if item.ServiceProtocol != "http" {
		return failure.Wrap("select an HTTP public URL", failure.InvalidCommand, errors.New("browser handoff requires an HTTP public URL"))
	}
	saved, found, err := s.store.ControlSession(ctx)
	if err != nil {
		return err
	}
	if !found {
		return failure.Wrap("select saved CLI session", failure.Authentication, errors.New("sign in with tnl auth login before creating a browser handoff"))
	}
	authority, err := authorityclient.New(s.authenticated.ServerEndpoint, nil, credentials.AccessToken(saved.AccessToken))
	if err != nil {
		return err
	}
	handoff, err := authority.IssueControlBrowserHandoff(ctx, item.Id, credentials.RefreshToken(saved.RefreshToken))
	if err != nil {
		return err
	}
	parsed, err := url.Parse(handoff)
	if err != nil || parsed.Scheme != "https" || parsed.Host != item.CanonicalHostname || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return failure.Wrap("validate browser handoff", failure.ServerResponseInvalid, errors.New("invalid browser handoff response"))
	}
	if err = openBrowser(handoff); err != nil {
		return failure.Wrap("open browser handoff", failure.BrowserOpenFailed, err)
	}
	return writeHumanFrame(output, "tnl auth browser", "opened", "", clioutput.Fields(clioutput.Field{Label: "public URL", Value: "https://" + item.CanonicalHostname}, clioutput.Field{Label: "session", Value: "browser session follows this CLI session's revocation"}))
}
