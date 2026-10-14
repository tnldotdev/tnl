package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type adminBrowserCommand struct {
	remoteFlags `embed:""`
	URL         string           `arg:"" name:"url" required:"" help:"Owned HTTP public URL ID, hostname, or HTTPS origin."`
	Open        bool             `name:"open" help:"Open the one-time handoff in your browser."`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

func selectAdminBrowserURL(selector string, inventory []controlv1.AvailablePublicURL) (controlv1.AvailablePublicURL, error) {
	hostname := selector
	if strings.HasPrefix(selector, "https://") {
		parsed, err := url.Parse(selector)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Host != parsed.Hostname() ||
			parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
			return controlv1.AvailablePublicURL{}, failure.Wrap("select browser public URL", failure.ShareInputInvalid, errors.New("use an HTTP public URL ID, hostname, or HTTPS origin"))
		}
		hostname = parsed.Hostname()
	}
	if !opaqueid.Valid(selector, opaqueid.PublicURLPrefix) {
		canonical, err := naming.CanonicalizeHostname(hostname)
		if err != nil || canonical != hostname {
			return controlv1.AvailablePublicURL{}, failure.Wrap("select browser public URL", failure.ShareInputInvalid, errors.New("use a canonical HTTP public URL"))
		}
	}
	for _, entry := range inventory {
		if entry.Id == selector || entry.CanonicalHostname == hostname && entry.ServiceProtocol == controlv1.Http {
			if entry.ServiceProtocol != controlv1.Http || entry.Purpose != controlv1.App || entry.VisitorAccess != "owner" {
				return controlv1.AvailablePublicURL{}, failure.Wrap("select browser public URL", failure.ShareInputInvalid, errors.New("select an owned HTTP app public URL"))
			}
			return entry, nil
		}
	}
	return controlv1.AvailablePublicURL{}, controlclient.ErrNotFound
}

func runAdminBrowserHandoff(ctx context.Context, flags adminBrowserCommand, output, diagnostics io.Writer) error {
	if flags.AccessToken != "" {
		return failure.Wrap("open administrator browser", failure.Authentication, errors.New("use a saved built-in administrator session from tnl auth login --login-token"))
	}
	session, err := openTeamSession(ctx, flags.remoteFlags, "tnl auth browser", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	if !session.identity.Identity.Administrator || session.authenticated.Discovery.BuiltinBrowserHandoffAvailable == nil ||
		!*session.authenticated.Discovery.BuiltinBrowserHandoffAvailable {
		return failure.Wrap("open administrator browser", failure.Authentication, errors.New("the selected server requires a built-in administrator login-token session"))
	}
	inventory, err := session.authenticated.Control.ListAvailablePublicURLs(ctx, "")
	if err != nil {
		return err
	}
	selected, err := selectAdminBrowserURL(flags.URL, inventory)
	if err != nil {
		return err
	}
	stored, found, err := session.store.ControlSession(ctx)
	if err != nil {
		return err
	}
	if !found || stored.RefreshPending || !stored.AccessExpiresAt.After(time.Now()) || !stored.RefreshExpiresAt.After(time.Now()) {
		return failure.Wrap("open administrator browser", failure.Authentication, errors.New("log in with tnl auth login --login-token, then retry"))
	}
	client, err := controlclient.New(session.authenticated.ServerEndpoint, nil, credentials.AccessToken(stored.AccessToken))
	if err != nil {
		return err
	}
	handoff, err := client.CreateAdminBrowserHandoff(ctx, selected.Id, stored.RefreshToken)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(handoff.EntryUrl)
	secret := ""
	if err == nil {
		secret = strings.TrimPrefix(parsed.Path, "/__tnl/team/handoff/")
	}
	raw, decodeErr := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || parsed.Scheme != "https" || parsed.Host != selected.CanonicalHostname || parsed.User != nil ||
		!strings.HasPrefix(parsed.Path, "/__tnl/team/handoff/") || len(raw) != 32 || decodeErr != nil ||
		base64.RawURLEncoding.EncodeToString(raw) != secret || parsed.RawQuery != "" || parsed.Fragment != "" ||
		!handoff.ExpiresAt.After(time.Now()) {
		return failure.Wrap("read browser handoff", failure.ServerResponseInvalid, errors.New("server returned an invalid public URL handoff"))
	}
	if flags.Open {
		if open := interactiveBrowserOpener(os.Stdin); open != nil {
			if err := open(handoff.EntryUrl); err != nil {
				return err
			}
		}
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write browser handoff", failure.OutputUnavailable, json.NewEncoder(output).Encode(handoff))
	}
	if err := writeHumanFrame(output, "tnl auth browser", "ready", "open the one-time URL in your browser", clioutput.Fields(
		clioutput.Field{Label: "public URL", Value: "https://" + selected.CanonicalHostname},
		clioutput.Field{Label: "expires", Value: handoff.ExpiresAt.UTC().Format(time.RFC3339)},
	)); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "open: "+handoff.EntryUrl)
	return failure.Wrap("write browser handoff", failure.OutputUnavailable, err)
}
