package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type shareCommand struct {
	Link linkShareCommand `cmd:"" help:"Create and revoke preview links."`
	Team teamShareCommand `cmd:"" help:"Share the preview with its team."`
	List shareListCommand `cmd:"" help:"List preview access for the selected team."`
}

type teamShareCommand struct {
	Create teamShareCreateCommand `cmd:"" help:"Let current team members visit this preview."`
	Revoke teamShareRevokeCommand `cmd:"" help:"Stop team-member access to this preview."`
}

type teamShareCreateCommand struct {
	scopedTeamFlags `embed:""`
	URL             string `arg:"" name:"url" optional:"" help:"Public URL ID, hostname, or HTTPS origin to open."`
}

type teamShareRevokeCommand struct {
	scopedTeamFlags `embed:""`
}

type linkShareCommand struct {
	Create shareCreateCommand `cmd:"" help:"Create a link for this preview."`
	Revoke shareRevokeCommand `cmd:"" help:"Revoke a link by ID."`
}

type shareCreateCommand struct {
	scopedTeamFlags `embed:""`
	URL             string `arg:"" name:"url" optional:"" help:"Public URL ID, hostname, or HTTPS origin to open."`
	ExpiresIn       string `name:"expires-in" default:"24h" help:"Link lifetime (for example, 24h or 7d; at most 30d)."`
}

type shareListCommand struct {
	scopedTeamFlags `embed:""`
	URL             string `arg:"" name:"url" optional:"" help:"Filter to the preview containing this public URL."`
}

type shareRevokeCommand struct {
	scopedTeamFlags `embed:""`
	ShareID         string `arg:"" name:"share-id" required:"" help:"Share ID to revoke."`
}

func parseShareLifetime(value string) (time.Duration, error) {
	var duration time.Duration
	var err error
	if days, found := strings.CutSuffix(value, "d"); found {
		count, parseErr := strconv.ParseUint(days, 10, 8)
		if parseErr != nil || count == 0 || count > 30 {
			return 0, failure.Wrap("validate share lifetime", failure.ShareInputInvalid, errors.New("share lifetime must be greater than zero and at most 30d"))
		}
		duration = time.Duration(count) * 24 * time.Hour
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

func previewShares(ctx context.Context, flags remoteFlags, project projectConfiguration, command string, diagnostics io.Writer) (*teamSession, controlv1.Preview, []controlv1.PublicURL, error) {
	if !project.Found() || len(project.Config.Services) == 0 {
		return nil, controlv1.Preview{}, nil, failure.Wrap("select share project", failure.PreviewNotSaved, errors.New("select a project with configured services; run tnl dev to publish its preview"))
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
		return nil, controlv1.Preview{}, nil, failure.Wrap("read share preview", failure.PreviewNotSaved, errors.New("preview is not saved for this checkout; run tnl dev first"))
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
		route, routeErr := session.authenticated.Control.GetPublicURLByHostname(ctx, current.team.Id, metadata.Services[name].Hostname)
		if routeErr != nil || !slices.Contains(preview.PublicUrlIds, route.Id) {
			session.Close()
			if routeErr != nil {
				return nil, controlv1.Preview{}, nil, fmt.Errorf("service %q: %w", name, routeErr)
			}
			return nil, controlv1.Preview{}, nil, failure.Wrap("resolve preview services", failure.PreviewStateConflict, fmt.Errorf("service %q is not yet in this preview; run tnl dev again", name))
		}
		routes = append(routes, route)
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
	_, err = fmt.Fprintf(output, "https://%s/__tnl/share/%s.%s\n", selected.CanonicalHostname, share.Id, base64.RawURLEncoding.EncodeToString(secret))
	return failure.Wrap("write share URL", failure.OutputUnavailable, err)
}

func runShareList(ctx context.Context, flags shareListCommand, project projectConfiguration, output, diagnostics io.Writer) error {
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
	selectedID := ""
	if flags.URL != "" {
		routes, err := session.authenticated.Control.ListPublicURLs(ctx, current.team.Id)
		if err != nil {
			return err
		}
		selected, err := selectSharePublicURL(flags.URL, routes)
		if err != nil {
			return err
		}
		selectedID = selected.Id
		shares = slices.DeleteFunc(shares, func(share controlv1.Share) bool {
			return !slices.Contains(share.PublicUrlIds, selected.Id)
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
				(selectedID == "" || slices.Contains(preview.PublicUrlIds, selectedID)) {
				teamGrant = true
				blocks = append(blocks, clioutput.Section("team", clioutput.Fields(
					clioutput.Field{Label: "team", Value: current.team.DisplayName},
					clioutput.Field{Label: "scope", Value: "current team members; preview-wide"},
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
	count := len(shares)
	if teamGrant {
		count++
	}
	return writeHumanFrame(output, "tnl share list", countState(count, "share", "shares"), "", blocks...)
}

func runShareTeamCreate(ctx context.Context, flags teamShareCreateCommand, project projectConfiguration, output, diagnostics io.Writer) error {
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
	team, err := session.api.GetTeam(ctx, preview.TeamId)
	if err != nil {
		return err
	}
	if team.Id != preview.TeamId || team.DisplayName == "" {
		return failure.Wrap("read sharing team", failure.ServerResponseInvalid, errors.New("server returned a different sharing team"))
	}
	updated, err := session.authenticated.Control.SetPreviewTeamAccess(ctx, preview.Id, true)
	if err != nil {
		return err
	}
	if updated.Id != preview.Id || updated.TeamId != preview.TeamId || updated.TeamAccessEnabled == nil || !*updated.TeamAccessEnabled {
		return failure.Wrap("enable team browser access", failure.ServerResponseInvalid, errors.New("server did not enable this preview's team access"))
	}
	return writeTeamShareCreated(output, team.DisplayName, updated, selected)
}

func writeTeamShareCreated(output io.Writer, teamName string, preview controlv1.Preview, entry controlv1.PublicURL) error {
	return writeHumanFrame(output, "tnl share team create", "shared", "team access applies to this whole preview", clioutput.Fields(
		clioutput.Field{Label: "team", Value: teamName},
		clioutput.Field{Label: "scope", Value: "current team members; all " + strconv.Itoa(len(preview.PublicUrlIds)) + " public URLs in this preview"},
		clioutput.Field{Label: "entry URL", Value: "https://" + entry.CanonicalHostname + "/"},
		clioutput.Field{Label: "revoke", Value: "tnl share team revoke --team " + teamName},
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
		return failure.Wrap("read share preview", failure.PreviewNotSaved, errors.New("preview is not saved for this checkout; run tnl dev first"))
	}
	updated, err := session.authenticated.Control.SetPreviewTeamAccess(ctx, id, false)
	if err != nil {
		return err
	}
	if updated.Id != id || updated.TeamId != current.team.Id || updated.TeamAccessEnabled == nil || *updated.TeamAccessEnabled {
		return failure.Wrap("revoke team browser access", failure.ServerResponseInvalid, errors.New("server did not revoke this preview's team access"))
	}
	return writeHumanFrame(output, "tnl share team revoke", "revoked", "", clioutput.Fields(
		clioutput.Field{Label: "team", Value: current.team.DisplayName},
		clioutput.Field{Label: "scope", Value: "all " + strconv.Itoa(len(updated.PublicUrlIds)) + " public URLs in this preview"},
	))
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
	return writeHumanFrame(output, "tnl share link revoke", "revoked", "", clioutput.Fields(clioutput.Field{Label: "share ID", Value: share.Id}))
}
