package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type shareCommand struct {
	Link   linkShareCommand   `cmd:"" help:"Create and revoke preview links."`
	Team   teamShareCommand   `cmd:"" help:"Share a preview or exact public URL with its team."`
	Invite inviteShareCommand `cmd:"" help:"Invite a named person to one public URL."`
	List   shareListCommand   `cmd:"" help:"List preview links, team shares, and named invitations."`
	Revoke shareRevokeCommand `cmd:"" help:"Revoke a share by ID."`
}

type teamShareCommand struct {
	Create teamShareCreateCommand `cmd:"" help:"Let current team members visit this preview."`
	Revoke teamShareRevokeCommand `cmd:"" help:"Stop team-member access to this preview."`
}

type teamShareCreateCommand struct {
	scopedTeamFlags `embed:""`
	URL             string           `arg:"" name:"url" optional:"" help:"Public URL ID, hostname, HTTPS origin, or database hostname:port."`
	ExpiresIn       string           `name:"expires-in" help:"Optional exact public URL share lifetime (at most 30d)."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type teamShareRevokeCommand struct {
	scopedTeamFlags `embed:""`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type linkShareCommand struct {
	Create shareCreateCommand `cmd:"" help:"Create a link for this preview."`
	Revoke shareRevokeCommand `cmd:"" help:"Revoke a link by ID."`
}

type shareCreateCommand struct {
	scopedTeamFlags `embed:""`
	URL             string           `arg:"" name:"url" optional:"" help:"Public URL ID, hostname, or HTTPS origin to open."`
	ExpiresIn       string           `name:"expires-in" default:"24h" help:"Link lifetime (for example, 24h or 7d; at most 30d)."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type shareListCommand struct {
	scopedTeamFlags `embed:""`
	URL             string           `arg:"" name:"url" optional:"" help:"Filter to the preview containing this public URL."`
	FilterURL       string           `name:"url" help:"Filter to one public URL ID, hostname, or hostname:port."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type shareRevokeCommand struct {
	scopedTeamFlags `embed:""`
	ShareID         string           `arg:"" name:"share-id" required:"" help:"Share ID to revoke."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type shareServiceResult struct {
	PublicURLID string `json:"public_url_id"`
	PublicURL   string `json:"public_url"`
}

func shareServiceURLs(project projectConfiguration, routes []controlv1.PublicURL) map[string]shareServiceResult {
	names := make([]string, 0, len(project.Config.Services))
	for name := range project.Config.Services {
		effective, err := project.EffectiveService(name)
		if err == nil && config.ServiceProtocol(effective.Publish) == "http" {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	services := make(map[string]shareServiceResult, len(routes))
	for index, route := range routes {
		services[names[index]] = shareServiceResult{PublicURLID: route.Id, PublicURL: "https://" + route.CanonicalHostname}
	}
	return services
}

func parseShareLifetime(value string) (time.Duration, error) {
	var duration time.Duration
	var err error
	if days, found, parseErr := parseWholeDayDuration(value, 30); found {
		if parseErr != nil {
			return 0, failure.Wrap("validate share lifetime", failure.ShareInputInvalid, errors.New("share lifetime must be greater than zero and at most 30d"))
		}
		duration = days
	} else {
		duration, err = time.ParseDuration(value)
		if err != nil || duration <= 0 || duration > 30*24*time.Hour {
			return 0, failure.Wrap("validate share lifetime", failure.ShareInputInvalid, errors.Join(err, errors.New("share lifetime must be greater than zero and at most 30d")))
		}
	}
	return duration, nil
}

func selectSharePublicURL(selector string, routes []controlv1.PublicURL) (controlv1.PublicURL, error) {
	if selector == "" {
		if len(routes) == 1 {
			return routes[0], nil
		}
		return controlv1.PublicURL{}, failure.Wrap("select share public URL", failure.ShareInputInvalid, errors.New("select the public URL to open, for example tnl share link create web.example.com"))
	}
	hostname := selector
	if strings.HasPrefix(selector, "https://") {
		parsed, err := url.Parse(selector)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Host != parsed.Hostname() || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
			return controlv1.PublicURL{}, failure.Wrap("validate share public URL", failure.ShareInputInvalid, errors.Join(err, errors.New("share URL must be a public URL ID, bare hostname, or HTTPS origin")))
		}
		hostname = parsed.Hostname()
	}
	if !opaqueid.Valid(selector, opaqueid.PublicURLPrefix) {
		canonical, err := naming.CanonicalizeHostname(hostname)
		if err != nil || canonical != hostname {
			return controlv1.PublicURL{}, failure.Wrap("validate share public URL", failure.ShareInputInvalid, errors.Join(err, errors.New("share URL must be a public URL ID, bare hostname, or HTTPS origin")))
		}
	}
	for _, route := range routes {
		if route.Id == selector || route.CanonicalHostname == hostname {
			return route, nil
		}
	}
	return controlv1.PublicURL{}, controlclient.ErrNotFound
}

func selectTeamSharePublicURL(selector string, routes []controlv1.PublicURL) (controlv1.PublicURL, error) {
	if opaqueid.Valid(selector, opaqueid.PublicURLPrefix) {
		for _, route := range routes {
			if route.Id == selector {
				return route, nil
			}
		}
		return controlv1.PublicURL{}, controlclient.ErrNotFound
	}
	if strings.HasPrefix(selector, "https://") {
		httpRoutes := slices.DeleteFunc(slices.Clone(routes), func(route controlv1.PublicURL) bool {
			return route.ServiceProtocol != controlv1.Http
		})
		selected, err := selectSharePublicURL(selector, httpRoutes)
		if err != nil || selected.ServiceProtocol != controlv1.Http {
			return controlv1.PublicURL{}, failure.Wrap("select team share public URL", failure.ShareInputInvalid, errors.New("an HTTPS origin must name an HTTP app public URL"))
		}
		return selected, nil
	}
	hostname, port := selector, 0
	if strings.Contains(selector, ":") {
		host, number, err := net.SplitHostPort(selector)
		if err != nil {
			return controlv1.PublicURL{}, failure.Wrap("select team share public URL", failure.ShareInputInvalid, errors.New("use a public URL ID or hostname:port for a database"))
		}
		hostname, port = host, parseTeamSharePort(number)
		if port == 0 {
			return controlv1.PublicURL{}, failure.Wrap("select team share public URL", failure.ShareInputInvalid, errors.New("use the assigned public TCP port"))
		}
	}
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return controlv1.PublicURL{}, failure.Wrap("select team share public URL", failure.ShareInputInvalid, errors.New("use a canonical public URL hostname"))
	}
	var selected controlv1.PublicURL
	for _, route := range routes {
		if route.CanonicalHostname != hostname || port != 0 && (route.PublicPort == nil || *route.PublicPort != port) {
			continue
		}
		if selected.Id != "" {
			return controlv1.PublicURL{}, failure.Wrap("select team share public URL", failure.ShareInputInvalid, errors.New("hostname selects more than one public URL; include its port or ID"))
		}
		selected = route
	}
	if selected.Id == "" {
		return controlv1.PublicURL{}, controlclient.ErrNotFound
	}
	return selected, nil
}

func parseTeamSharePort(value string) int {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1024 || port > 65535 || strconv.Itoa(port) != value {
		return 0
	}
	return port
}

func previewShares(ctx context.Context, flags remoteFlags, project projectConfiguration, command string, diagnostics io.Writer) (*teamSession, controlv1.Preview, []controlv1.PublicURL, error) {
	if !project.Found() || len(project.Config.Services) == 0 {
		return nil, controlv1.Preview{}, nil, failure.Wrap("select share project", failure.PreviewNotSaved, errors.New("select a project with configured services, then start your app"))
	}
	session, err := openTeamSession(ctx, flags, command, diagnostics)
	if err != nil {
		return nil, controlv1.Preview{}, nil, err
	}
	current, err := session.current(ctx)
	if err != nil {
		session.Close()
		return nil, controlv1.Preview{}, nil, err
	}
	id, found, err := session.store.PreviewID(ctx, current.team.Id, project.Root)
	if err != nil || !found {
		session.Close()
		if err != nil {
			return nil, controlv1.Preview{}, nil, err
		}
		return nil, controlv1.Preview{}, nil, failure.Wrap("read share preview", failure.PreviewNotSaved, errors.New("preview is not saved for this checkout; start a configured app service first"))
	}
	preview, err := session.authenticated.Control.GetPreview(ctx, id)
	if err != nil || preview.TeamId != current.team.Id || preview.Id != id {
		session.Close()
		if err != nil {
			return nil, controlv1.Preview{}, nil, err
		}
		return nil, controlv1.Preview{}, nil, failure.Wrap("read share preview", failure.ServerResponseInvalid, errors.New("server returned a preview for another team"))
	}
	resolver := newProjectMetadataResolver(session.database, project, os.Stdin, diagnostics, command)
	resolver.Seed(session.authenticated.ServerEndpoint, session.authenticated)
	metadata, err := resolver.Generate(ctx)
	if err != nil {
		session.Close()
		return nil, controlv1.Preview{}, nil, err
	}
	names := make([]string, 0, len(metadata.Services))
	for name := range metadata.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	routes := make([]controlv1.PublicURL, 0, len(names))
	for _, name := range names {
		effective, err := project.EffectiveService(name)
		if err != nil {
			session.Close()
			return nil, controlv1.Preview{}, nil, err
		}
		if config.ServiceProtocol(effective.Publish) != "http" {
			continue
		}
		route, routeErr := session.authenticated.Control.GetPublicURLByHostname(ctx, current.team.Id, metadata.Services[name].Hostname)
		if routeErr != nil || !slices.Contains(preview.PublicUrlIds, route.Id) || route.ServiceProtocol != controlv1.Http {
			session.Close()
			if routeErr != nil {
				return nil, controlv1.Preview{}, nil, fmt.Errorf("service %q: %w", name, routeErr)
			}
			return nil, controlv1.Preview{}, nil, failure.Wrap("resolve preview services", failure.PreviewStateConflict, fmt.Errorf("service %q is not yet in this preview; start it with its tnl integration", name))
		}
		routes = append(routes, route)
	}
	if len(routes) == 0 {
		session.Close()
		return nil, controlv1.Preview{}, nil, failure.Wrap("select share public URL", failure.ShareInputInvalid, errors.New("configure an HTTP app service to create a preview share"))
	}
	return session, preview, routes, nil
}

func runShareCreate(ctx context.Context, flags shareCreateCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	lifetime, err := parseShareLifetime(flags.ExpiresIn)
	if err != nil {
		return err
	}
	session, preview, routes, err := previewShares(ctx, flags.selection(), project, "tnl share link create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	selected, err := selectSharePublicURL(flags.URL, routes)
	if err != nil {
		return err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate share secret: %w", err)
	}
	fingerprint := sha256.Sum256(secret)
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(routes))
	for _, route := range routes {
		ids = append(ids, route.Id)
	}
	slices.Sort(ids)
	share, err := session.authenticated.Control.CreateShare(ctx, preview.Id, key, controlv1.CreateShareRequest{
		PublicUrlIds: ids, ExpiresAt: time.Now().UTC().Add(lifetime), SecretFingerprint: hex.EncodeToString(fingerprint[:]),
	})
	if err != nil {
		return err
	}
	if share.Id == "" || share.PreviewId != preview.Id || !slices.Equal(share.PublicUrlIds, ids) {
		return failure.Wrap("create preview share", failure.ServerResponseInvalid, errors.New("server returned a share with different public URLs"))
	}
	entry := fmt.Sprintf("https://%s/__tnl/share/%s.%s", selected.CanonicalHostname, share.Id, base64.RawURLEncoding.EncodeToString(secret))
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write share URL", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion int                           `json:"schema_version"`
			ShareID       string                        `json:"share_id"`
			PreviewID     string                        `json:"preview_id"`
			EntryURL      string                        `json:"entry_url"`
			PublicURLIDs  []string                      `json:"public_url_ids"`
			Services      map[string]shareServiceResult `json:"services"`
			ExpiresAt     time.Time                     `json:"expires_at"`
		}{1, share.Id, preview.Id, entry, ids, shareServiceURLs(project, routes), share.ExpiresAt}))
	}
	_, err = fmt.Fprintln(output, entry)
	return failure.Wrap("write share URL", failure.OutputUnavailable, err)
}

func runShareList(ctx context.Context, flags shareListCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.URL != "" && flags.FilterURL != "" {
		return failure.Wrap("filter shares", failure.ShareInputInvalid, errors.New("select one public URL with a positional URL or --url"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl share list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	shares, err := session.authenticated.Control.ListTeamShares(ctx, current.team.Id)
	if err != nil {
		return err
	}
	grants, err := session.authenticated.Control.ListShareGrants(ctx, current.team.Id)
	if err != nil {
		return err
	}
	invitations, err := session.authenticated.Control.ListVisitorInvitations(ctx, current.team.Id)
	if err != nil {
		return err
	}
	selectedID := ""
	selectedHTTP := false
	selector := flags.URL
	if flags.FilterURL != "" {
		selector = flags.FilterURL
	}
	if selector != "" {
		routes, err := session.authenticated.Control.ListPublicURLs(ctx, current.team.Id)
		if err != nil {
			return err
		}
		selected, err := selectTeamSharePublicURL(selector, routes)
		if err != nil {
			return err
		}
		selectedID = selected.Id
		selectedHTTP = selected.ServiceProtocol == controlv1.Http
		shares = slices.DeleteFunc(shares, func(share controlv1.Share) bool {
			return !slices.Contains(share.PublicUrlIds, selected.Id)
		})
		grants = slices.DeleteFunc(grants, func(grant controlv1.ShareGrant) bool {
			return grant.PublicUrlId != selected.Id
		})
		invitations = slices.DeleteFunc(invitations, func(invitation controlv1.VisitorInvitation) bool {
			return invitation.PublicUrlId != selected.Id
		})
	}
	blocks := make([]clioutput.Block, 0, len(shares))
	teamGrant := false
	if project.Found() && project.Root != "" {
		id, found, err := session.store.PreviewID(ctx, current.team.Id, project.Root)
		if err != nil {
			return err
		}
		if found {
			preview, err := session.authenticated.Control.GetPreview(ctx, id)
			if err != nil {
				return err
			}
			if preview.TeamId == current.team.Id && preview.TeamAccessEnabled != nil && *preview.TeamAccessEnabled &&
				(selectedID == "" || selectedHTTP) &&
				(selectedID == "" || slices.Contains(preview.PublicUrlIds, selectedID)) {
				teamGrant = true
				blocks = append(blocks, clioutput.Section("team", clioutput.Fields(
					clioutput.Field{Label: "preview ID", Value: preview.Id},
					clioutput.Field{Label: "public URLs", Value: strconv.Itoa(len(preview.PublicUrlIds))},
				)))
			}
		}
	}
	for _, share := range shares {
		state := "active"
		if share.RevokedAt != nil {
			state = "revoked"
		} else if !share.ExpiresAt.After(time.Now()) {
			state = "expired"
		}
		blocks = append(blocks, clioutput.Section(share.Id, clioutput.Fields(
			clioutput.Field{Label: "state", Value: state},
			clioutput.Field{Label: "expires", Value: share.ExpiresAt.UTC().Format(time.RFC3339)},
			clioutput.Field{Label: "public URLs", Value: strconv.Itoa(len(share.PublicUrlIds))},
		)))
	}
	for _, grant := range grants {
		state := "active"
		if grant.RevokedAt != nil {
			state = "revoked"
		} else if grant.ExpiresAt != nil && !grant.ExpiresAt.After(time.Now()) {
			state = "expired"
		}
		fields := []clioutput.Field{
			{Label: "kind", Value: string(grant.Kind)},
			{Label: "state", Value: state},
			{Label: "public URL ID", Value: grant.PublicUrlId},
		}
		if grant.ExpiresAt != nil {
			fields = append(fields, clioutput.Field{Label: "expires", Value: grant.ExpiresAt.UTC().Format(time.RFC3339)})
		}
		blocks = append(blocks, clioutput.Section(grant.Id, clioutput.Fields(fields...)))
	}
	for _, invitation := range invitations {
		state := "pending"
		switch {
		case invitation.RevokedAt != nil:
			state = "revoked"
		case !invitation.ExpiresAt.After(time.Now()):
			state = "expired"
		case invitation.AcceptedAt != nil:
			state = "accepted"
		}
		blocks = append(blocks, clioutput.Section(invitation.Id, clioutput.Fields(
			clioutput.Field{Label: "kind", Value: "invite"},
			clioutput.Field{Label: "state", Value: state},
			clioutput.Field{Label: "email", Value: invitation.Email},
			clioutput.Field{Label: "public URL ID", Value: invitation.PublicUrlId},
			clioutput.Field{Label: "expires", Value: invitation.ExpiresAt.UTC().Format(time.RFC3339)},
		)))
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write share list", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion     int                           `json:"schema_version"`
			Shares            []controlv1.Share             `json:"shares"`
			Grants            []controlv1.ShareGrant        `json:"grants"`
			Invitations       []controlv1.VisitorInvitation `json:"invitations"`
			TeamAccessEnabled bool                          `json:"team_access_enabled"`
		}{1, shares, grants, invitations, teamGrant}))
	}
	count := len(shares) + len(grants) + len(invitations)
	if teamGrant {
		count++
	}
	return writeHumanFrame(output, "tnl share list", countState(count, "share", "shares"), "", blocks...)
}

func runShareTeamCreate(ctx context.Context, flags teamShareCreateCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.URL != "" {
		session, err := openTeamSession(ctx, flags.selection(), "tnl share team create", diagnostics)
		if err != nil {
			return err
		}
		defer session.Close()
		current, err := session.current(ctx)
		if err != nil {
			return err
		}
		routes, err := session.authenticated.Control.ListPublicURLs(ctx, current.team.Id)
		if err != nil {
			return err
		}
		selected, err := selectTeamSharePublicURL(flags.URL, routes)
		if err != nil {
			return err
		}
		if selected.ServiceProtocol != controlv1.Http && selected.ServiceProtocol != controlv1.Postgres &&
			selected.ServiceProtocol != controlv1.Mysql && selected.ServiceProtocol != controlv1.Redis {
			return failure.Wrap("select team share public URL", failure.ShareInputInvalid, errors.New("team sharing supports HTTP apps and databases"))
		}
		exact := selected.ServiceProtocol != controlv1.Http || flags.ExpiresIn != "" || !project.Found()
		if !exact {
			previewID, found, err := session.store.PreviewID(ctx, current.team.Id, project.Root)
			if err != nil {
				return err
			}
			if found {
				preview, err := session.authenticated.Control.GetPreview(ctx, previewID)
				if err != nil {
					return err
				}
				exact = !slices.Contains(preview.PublicUrlIds, selected.Id)
			} else {
				exact = true
			}
		}
		if exact {
			var expires *time.Time
			if flags.ExpiresIn != "" {
				lifetime, err := parseShareLifetime(flags.ExpiresIn)
				if err != nil {
					return err
				}
				value := time.Now().UTC().Add(lifetime)
				expires = &value
			}
			key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				return err
			}
			grant, err := session.authenticated.Control.CreateShareGrant(ctx, key, controlv1.CreateShareGrantRequest{
				TeamId: current.team.Id, PublicUrlId: selected.Id, ExpiresAt: expires,
			})
			if err != nil {
				return err
			}
			if grant.TeamId != current.team.Id || grant.PublicUrlId != selected.Id || grant.Id == "" {
				return failure.Wrap("create team share", failure.ServerResponseInvalid, errors.New("server returned a share for another public URL"))
			}
			address, err := savedPublicAddress(selected)
			if err != nil {
				return err
			}
			if flags.Output == statusOutputJSON {
				return failure.Wrap("write team share", failure.OutputUnavailable, json.NewEncoder(output).Encode(grant))
			}
			return writeHumanFrame(output, "tnl share team create", "shared", "", clioutput.Fields(
				clioutput.Field{Label: "public URL", Value: address}, clioutput.Field{Label: "share ID", Value: grant.Id},
			))
		}
	}
	if flags.ExpiresIn != "" {
		return failure.Wrap("validate team share", failure.ShareInputInvalid, errors.New("preview-wide team access lasts until revoked; select an exact URL with --expires-in"))
	}
	session, preview, routes, err := previewShares(ctx, flags.selection(), project, "tnl share team create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	selected, err := selectSharePublicURL(flags.URL, routes)
	if err != nil {
		return err
	}
	if session.authenticated.Discovery.BrowserLoginAvailable == nil || !*session.authenticated.Discovery.BrowserLoginAvailable {
		return failure.Wrap("enable team browser access", failure.ServerOIDCInvalid, errors.New("team access requires a server with OIDC browser sign-in; configure OIDC before sharing with the team"))
	}
	updated, err := session.authenticated.Control.SetPreviewTeamAccess(ctx, preview.Id, true)
	if err != nil {
		return err
	}
	if updated.Id != preview.Id || updated.TeamAccessEnabled == nil || !*updated.TeamAccessEnabled {
		return failure.Wrap("enable team browser access", failure.ServerResponseInvalid, errors.New("server did not enable this preview's team access"))
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write team access", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion int                           `json:"schema_version"`
			PreviewID     string                        `json:"preview_id"`
			PublicURL     string                        `json:"public_url"`
			Services      map[string]shareServiceResult `json:"services"`
			Enabled       bool                          `json:"enabled"`
		}{1, preview.Id, "https://" + selected.CanonicalHostname + "/", shareServiceURLs(project, routes), true}))
	}
	return writeHumanFrame(output, "tnl share team create", "shared", "", clioutput.Fields(
		clioutput.Field{Label: "public URL", Value: "https://" + selected.CanonicalHostname + "/"},
	))
}

func runShareTeamRevoke(ctx context.Context, flags teamShareRevokeCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if !project.Found() || project.Root == "" {
		return failure.Wrap("select share project", failure.PreviewNotSaved, errors.New("select a configured project to revoke this checkout's team access"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl share team revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	id, found, err := session.store.PreviewID(ctx, current.team.Id, project.Root)
	if err != nil {
		return err
	}
	if !found {
		return failure.Wrap("read share preview", failure.PreviewNotSaved, errors.New("preview is not saved for this checkout; start a configured app service first"))
	}
	updated, err := session.authenticated.Control.SetPreviewTeamAccess(ctx, id, false)
	if err != nil {
		return err
	}
	if updated.Id != id || updated.TeamAccessEnabled == nil || *updated.TeamAccessEnabled {
		return failure.Wrap("revoke team browser access", failure.ServerResponseInvalid, errors.New("server did not revoke this preview's team access"))
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write team access", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			PreviewID     string `json:"preview_id"`
			Enabled       bool   `json:"enabled"`
		}{1, id, false}))
	}
	return writeHumanFrame(output, "tnl share team revoke", "revoked", "", clioutput.Fields(clioutput.Field{Label: "preview ID", Value: id}))
}

func runShareRevoke(ctx context.Context, flags shareRevokeCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl share link revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	share, err := session.authenticated.Control.GetShare(ctx, flags.ShareID)
	if err != nil || share.TeamId != current.team.Id {
		if err != nil {
			return err
		}
		return controlclient.ErrNotFound
	}
	if _, err := session.authenticated.Control.RevokeShare(ctx, share.Id); err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write share revocation", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			ShareID       string `json:"share_id"`
			Revoked       bool   `json:"revoked"`
		}{1, share.Id, true}))
	}
	return writeHumanFrame(output, "tnl share link revoke", "revoked", "", clioutput.Fields(clioutput.Field{Label: "share ID", Value: share.Id}))
}

func runShareAnyRevoke(ctx context.Context, flags shareRevokeCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl share revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	grants, err := session.authenticated.Control.ListShareGrants(ctx, current.team.Id)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if grant.Id != flags.ShareID {
			continue
		}
		revoked, err := session.authenticated.Control.RevokeShareGrant(ctx, grant.Id)
		if err != nil {
			return err
		}
		if flags.Output == statusOutputJSON {
			return failure.Wrap("write share revocation", failure.OutputUnavailable, json.NewEncoder(output).Encode(revoked))
		}
		return writeHumanFrame(output, "tnl share revoke", "revoked", "", clioutput.Fields(clioutput.Field{Label: "share ID", Value: revoked.Id}))
	}
	invitations, err := session.authenticated.Control.ListVisitorInvitations(ctx, current.team.Id)
	if err != nil {
		return err
	}
	for _, invitation := range invitations {
		if invitation.Id != flags.ShareID {
			continue
		}
		revoked, err := session.authenticated.Control.RevokeVisitorInvitation(ctx, invitation.Id)
		if err != nil {
			return err
		}
		if flags.Output == statusOutputJSON {
			return failure.Wrap("write share revocation", failure.OutputUnavailable, json.NewEncoder(output).Encode(revoked))
		}
		return writeHumanFrame(output, "tnl share revoke", "revoked", "", clioutput.Fields(clioutput.Field{Label: "share ID", Value: revoked.Id}))
	}
	share, err := session.authenticated.Control.GetShare(ctx, flags.ShareID)
	if err != nil || share.TeamId != current.team.Id {
		if err != nil {
			return err
		}
		return controlclient.ErrNotFound
	}
	if _, err := session.authenticated.Control.RevokeShare(ctx, share.Id); err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write share revocation", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			ShareID       string `json:"share_id"`
			Revoked       bool   `json:"revoked"`
		}{1, share.Id, true}))
	}
	return writeHumanFrame(output, "tnl share revoke", "revoked", "", clioutput.Fields(clioutput.Field{Label: "share ID", Value: share.Id}))
}
