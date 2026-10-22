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
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type shareCommand struct {
	Service serviceShareCommand `cmd:"" help:"Manage access to one configured service or exact service ID."`
	Invite  shareInviteCommand  `cmd:"" help:"Invite a verified-email visitor without team membership."`
	Link    linkShareCommand    `cmd:"" help:"Create a browser share link."`
	Token   tokenShareCommand   `cmd:"" help:"Create a share token for an HTTP client."`
	Team    teamShareCommand    `cmd:"" help:"Share the preview with its team."`
	List    shareListCommand    `cmd:"" help:"List access for the selected team."`
	Revoke  shareRevokeCommand  `cmd:"" help:"Revoke a share by ID."`
}

type teamShareCommand struct {
	Create teamShareCreateCommand `cmd:"" help:"Let current team members visit this preview."`
	Revoke teamShareRevokeCommand `cmd:"" help:"Stop team-member access to this preview."`
}

type teamShareCreateCommand struct {
	ExpiresIn       string `name:"expires-in" help:"Exact URL grant lifetime; omit for perpetual access."`
	scopedTeamFlags `embed:""`
	URL             string           `arg:"" name:"url" optional:"" help:"Public URL ID, hostname, or HTTPS origin to open."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type teamShareRevokeCommand struct {
	URL             string `arg:"" optional:"" help:"Exact public URL whose team grants should be revoked; omit for this preview."`
	scopedTeamFlags `embed:""`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type linkShareCommand struct {
	Create shareCreateCommand `cmd:"" help:"Create a link for one public URL, or --preview for this preview."`
}

type shareCreateCommand struct {
	scopedTeamFlags `embed:""`
	URL             string           `arg:"" name:"url" optional:"" help:"Public URL ID, hostname, or HTTPS origin to open."`
	Preview         bool             `name:"preview" help:"Include every current HTTP public URL in this project preview."`
	Name            string           `name:"name" help:"Optional label shown when listing this share."`
	ExpiresIn       string           `name:"expires-in" default:"24h" help:"Share lifetime (for example, 24h or 7d; at most 30d)."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type tokenShareCommand struct {
	Create tokenShareCreateCommand `cmd:"" help:"Print a token for Tnl-Share-Token on one public URL."`
}

type tokenShareCreateCommand struct {
	shareCreateCommand `embed:""`
}

type shareListCommand struct {
	scopedTeamFlags `embed:""`
	URL             string           `arg:"" name:"url" optional:"" help:"Filter to access for this public URL."`
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

func shareServiceURLs(project projectConfiguration, routes []controlv1.PublicURL, hostnames map[string]string) map[string]shareServiceResult {
	byHostname := make(map[string]controlv1.PublicURL, len(routes))
	for _, publicURL := range routes {
		if publicURL.ServiceProtocol == controlv1.Http {
			byHostname[publicURL.CanonicalHostname] = publicURL
		}
	}
	services := make(map[string]shareServiceResult, len(routes))
	for name, service := range project.Config.Services {
		if !config.IsPublicService(service) {
			continue
		}
		if publicURL, found := byHostname[hostnames[name]]; found {
			services[name] = shareServiceResult{PublicURLID: publicURL.Id, PublicURL: "https://" + publicURL.CanonicalHostname}
		}
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
	for _, publicURL := range routes {
		if publicURL.Id == selector || publicURL.CanonicalHostname == hostname {
			return publicURL, nil
		}
	}
	return controlv1.PublicURL{}, clientcontrol.ErrNotFound
}

func previewShares(ctx context.Context, flags remoteFlags, project projectConfiguration, command string, diagnostics io.Writer, services map[string]shareServiceResult) (*clientteam.Session, controlv1.Preview, []controlv1.PublicURL, error) {
	if !project.Found() || len(project.Config.Services) == 0 {
		return nil, controlv1.Preview{}, nil, failure.Wrap("select share project", failure.PreviewNotSaved, errors.New("select a project with configured services, then start your app"))
	}
	session, err := openTeamSession(ctx, flags, command, diagnostics)
	if err != nil {
		return nil, controlv1.Preview{}, nil, err
	}
	current, err := session.Current(ctx)
	if err != nil {
		session.Close()
		return nil, controlv1.Preview{}, nil, err
	}
	id, found, err := session.Store().PreviewID(ctx, current.Team().Id, project.Root)
	if err != nil || !found {
		session.Close()
		if err != nil {
			return nil, controlv1.Preview{}, nil, err
		}
		return nil, controlv1.Preview{}, nil, failure.Wrap("read share preview", failure.PreviewNotSaved, errors.New("preview is not saved for this checkout; start a configured app service first"))
	}
	preview, err := session.Authenticated().Control.GetPreview(ctx, id)
	if err != nil || preview.TeamId != current.Team().Id || preview.Id != id {
		session.Close()
		if err != nil {
			return nil, controlv1.Preview{}, nil, err
		}
		return nil, controlv1.Preview{}, nil, failure.Wrap("read share preview", failure.ServerResponseInvalid, errors.New("server returned a preview for another team"))
	}
	resolver := resolve.NewMetadataResolver(session.Database(), project.Project, func(ctx context.Context, state *clientstate.Database, server string) (*auth.Client, error) {
		return projectAuthentication(ctx, state, server, command, os.Stdin, diagnostics)
	})
	resolver.Seed(session.Authenticated().ServerEndpoint, session.Authenticated())
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
	hostnames := make(map[string]string, len(names))
	for _, name := range names {
		publicURL, routeErr := session.Authenticated().Control.GetPublicURLByHostname(ctx, current.Team().Id, metadata.Services[name].Hostname)
		if routeErr == nil && publicURL.ServiceProtocol != controlv1.Http {
			continue
		}
		if routeErr != nil || !slices.Contains(preview.PublicUrlIds, publicURL.Id) {
			session.Close()
			if routeErr != nil {
				return nil, controlv1.Preview{}, nil, fmt.Errorf("service %q: %w", name, routeErr)
			}
			return nil, controlv1.Preview{}, nil, failure.Wrap("resolve preview services", failure.PreviewStateConflict, fmt.Errorf("service %q is not yet in this preview; start it with its tnl integration", name))
		}
		routes = append(routes, publicURL)
		hostnames[name] = metadata.Services[name].Hostname
	}
	for name, service := range shareServiceURLs(project, routes, hostnames) {
		services[name] = service
	}
	return session, preview, routes, nil
}

func runShareCreate(ctx context.Context, flags shareCreateCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	return createShare(ctx, flags, project, false, output, diagnostics)
}

func runShareTokenCreate(ctx context.Context, flags tokenShareCreateCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.Preview {
		return failure.Wrap("select share scope", failure.ShareInputInvalid, errors.New("automation tokens require one public URL; omit --preview"))
	}
	if flags.Name == "" {
		return failure.Wrap("name share token", failure.ShareInputInvalid, errors.New("set --name to identify the automation using this share"))
	}
	return createShare(ctx, flags.shareCreateCommand, project, true, output, diagnostics)
}

func createShare(ctx context.Context, flags shareCreateCommand, project projectConfiguration, token bool, output, diagnostics io.Writer) error {
	lifetime, err := parseShareLifetime(flags.ExpiresIn)
	if err != nil {
		return err
	}
	if len(flags.Name) > 128 {
		return failure.Wrap("name share", failure.ShareInputInvalid, errors.New("share name must be at most 128 characters"))
	}
	command := "tnl share link create"
	if token {
		command = "tnl share token create"
	}
	var session *clientteam.Session
	var preview controlv1.Preview
	var routes []controlv1.PublicURL
	services := make(map[string]shareServiceResult)
	if flags.Preview || flags.URL == "" {
		session, preview, routes, err = previewShares(ctx, flags.selection(), project, command, diagnostics, services)
	} else {
		session, err = openTeamSession(ctx, flags.selection(), command, diagnostics)
		if err == nil {
			current, currentErr := session.Current(ctx)
			if currentErr != nil {
				err = currentErr
			} else {
				routes, err = session.Authenticated().Control.ListPublicURLs(ctx, current.Team().Id)
			}
		}
	}
	if err != nil {
		if session != nil {
			session.Close()
		}
		return err
	}
	defer session.Close()
	selected, err := selectSharePublicURL(flags.URL, routes)
	if err != nil {
		return err
	}
	if selected.ServiceProtocol != controlv1.Http {
		return failure.Wrap("select share public URL", failure.ShareInputInvalid, errors.New("share links and tokens require an HTTP public URL"))
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
	ids := []string{selected.Id}
	if flags.Preview {
		ids = anonymousPreviewPublicURLIDs(routes)
	}
	request := controlv1.CreateShareRequest{
		PublicUrlIds: ids, ExpiresAt: time.Now().UTC().Add(lifetime), SecretFingerprint: hex.EncodeToString(fingerprint[:]),
		Label: &flags.Name,
	}
	var share controlv1.Share
	if flags.Preview {
		share, err = session.Authenticated().Control.CreateShare(ctx, preview.Id, key, request)
	} else {
		share, err = session.Authenticated().Control.CreateURLShare(ctx, key, request)
	}
	if err != nil {
		return err
	}
	if share.Id == "" || !slices.Equal(share.PublicUrlIds, ids) || flags.Preview && (share.PreviewId == nil || *share.PreviewId != preview.Id) || !flags.Preview && share.PreviewId != nil {
		return failure.Wrap("create share", failure.ServerResponseInvalid, errors.New("server returned a share with different public URLs"))
	}
	capability := share.Id + "." + base64.RawURLEncoding.EncodeToString(secret)
	entry := "https://" + selected.CanonicalHostname + "/__tnl/share/" + capability
	if flags.Output == statusOutputJSON {
		if token {
			return failure.Wrap("write share token", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
				SchemaVersion int       `json:"schema_version"`
				ShareID       string    `json:"share_id"`
				ShareToken    string    `json:"share_token"`
				PublicURLID   string    `json:"public_url_id"`
				ExpiresAt     time.Time `json:"expires_at"`
			}{1, share.Id, capability, selected.Id, share.ExpiresAt}))
		}
		return failure.Wrap("write share URL", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion int                           `json:"schema_version"`
			ShareID       string                        `json:"share_id"`
			PreviewID     *string                       `json:"preview_id,omitempty"`
			EntryURL      string                        `json:"entry_url"`
			PublicURLIDs  []string                      `json:"public_url_ids"`
			Services      map[string]shareServiceResult `json:"services,omitempty"`
			ExpiresAt     time.Time                     `json:"expires_at"`
		}{1, share.Id, share.PreviewId, entry, ids, shareServices(services, flags.Preview), share.ExpiresAt}))
	}
	if token {
		_, err = fmt.Fprintln(output, capability)
		return failure.Wrap("write share token", failure.OutputUnavailable, err)
	}
	_, err = fmt.Fprintln(output, entry)
	return failure.Wrap("write share URL", failure.OutputUnavailable, err)
}

func anonymousPreviewPublicURLIDs(routes []controlv1.PublicURL) []string {
	ids := make([]string, 0, len(routes))
	for _, publicURL := range routes {
		if publicURL.ServiceProtocol == controlv1.Http {
			ids = append(ids, publicURL.Id)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func shareServices(services map[string]shareServiceResult, preview bool) map[string]shareServiceResult {
	if !preview {
		return nil
	}
	return services
}

func runShareList(ctx context.Context, flags shareListCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.URL != "" {
		return runExactShareList(ctx, flags.selection(), flags.URL, flags.Output, output, diagnostics)
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl share list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	shares, err := session.Authenticated().Control.ListTeamShares(ctx, current.Team().Id)
	if err != nil {
		return err
	}
	selectedID := ""
	if flags.URL != "" {
		routes, err := session.Authenticated().Control.ListPublicURLs(ctx, current.Team().Id)
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
		id, found, err := session.Store().PreviewID(ctx, current.Team().Id, project.Root)
		if err != nil {
			return err
		}
		if found {
			preview, err := session.Authenticated().Control.GetPreview(ctx, id)
			if err != nil {
				return err
			}
			if preview.TeamId == current.Team().Id && preview.TeamAccessEnabled != nil && *preview.TeamAccessEnabled &&
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
		fields := []clioutput.Field{
			{Label: "scope", Value: string(share.Scope)},
			{Label: "state", Value: state},
			{Label: "expires", Value: share.ExpiresAt.UTC().Format(time.RFC3339)},
			{Label: "public URLs", Value: strconv.Itoa(len(share.PublicUrlIds))},
		}
		if share.Label != "" {
			fields = append(fields, clioutput.Field{Label: "name", Value: share.Label})
		}
		blocks = append(blocks, clioutput.Section(share.Id, clioutput.Fields(fields...)))
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write share list", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion     int               `json:"schema_version"`
			Shares            []controlv1.Share `json:"shares"`
			TeamAccessEnabled bool              `json:"team_access_enabled"`
		}{1, shares, teamGrant}))
	}
	count := len(shares)
	if teamGrant {
		count++
	}
	return writeHumanFrame(output, "tnl share list", countState(count, "share", "shares"), "", blocks...)
}

func runExactShareList(ctx context.Context, flags remoteFlags, selector string, mode statusOutputMode, output, diagnostics io.Writer) error {
	s, err := openTeamSession(ctx, flags, "tnl share list", diagnostics)
	if err != nil {
		return err
	}
	defer s.Close()
	item, err := resolveVisitorPublicURL(ctx, s, selector)
	if err != nil {
		return err
	}
	grants, err := s.Authenticated().Control.ListVisitorGrants(ctx, item.Id)
	if err != nil {
		return err
	}
	invitations, err := s.Authenticated().Control.ListVisitorInvitations(ctx, item.Id)
	if err != nil {
		return err
	}
	shares, err := s.Authenticated().Control.ListTeamShares(ctx, item.TeamId)
	if err != nil {
		return err
	}
	shares = slices.DeleteFunc(shares, func(share controlv1.Share) bool { return !slices.Contains(share.PublicUrlIds, item.Id) })
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			Grants      []controlv1.VisitorGrant      `json:"grants"`
			Invitations []controlv1.VisitorInvitation `json:"invitations"`
			Shares      []controlv1.Share             `json:"shares"`
		}{grants, invitations, shares})
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "public URL ID", Value: item.Id})}
	for _, grant := range grants {
		expiry := "perpetual"
		state := "active"
		if grant.ExpiresAt != nil {
			expiry = grant.ExpiresAt.UTC().Format(time.RFC3339)
			if !grant.ExpiresAt.After(time.Now()) {
				state = "expired"
			}
		}
		if grant.RevokedAt != nil {
			state = "revoked"
		}
		fields := []clioutput.Field{{Label: "kind", Value: string(grant.Kind)}, {Label: "state", Value: state}, {Label: "expires", Value: expiry}}
		blocks = append(blocks, clioutput.Section(grant.Id, clioutput.Fields(fields...)))
	}
	for _, invitation := range invitations {
		fields := []clioutput.Field{{Label: "email", Value: invitation.Email}, {Label: "expires", Value: invitation.ExpiresAt.UTC().Format(time.RFC3339)}}
		blocks = append(blocks, clioutput.Section(invitation.Id, clioutput.Fields(fields...)))
	}
	for _, share := range shares {
		fields := []clioutput.Field{{Label: "scope", Value: string(share.Scope)}, {Label: "expires", Value: share.ExpiresAt.UTC().Format(time.RFC3339)}}
		if share.Label != "" {
			fields = append(fields, clioutput.Field{Label: "name", Value: share.Label})
		}
		blocks = append(blocks, clioutput.Section(share.Id, clioutput.Fields(fields...)))
	}
	return writeHumanFrame(output, "tnl share list", countState(len(grants)+len(invitations)+len(shares), "share", "shares"), "", blocks...)
}

func runShareTeamCreate(ctx context.Context, flags teamShareCreateCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.URL != "" {
		return runExactTeamShare(ctx, flags.selection(), flags.URL, flags.ExpiresIn, false, flags.Output, output, diagnostics)
	}
	if flags.ExpiresIn != "" {
		return failure.Wrap("select expiring team grant", failure.ShareInputInvalid, errors.New("an expiring team grant requires an exact public URL"))
	}
	services := make(map[string]shareServiceResult)
	session, preview, routes, err := previewShares(ctx, flags.selection(), project, "tnl share team create", diagnostics, services)
	if err != nil {
		return err
	}
	defer session.Close()
	selected, err := selectSharePublicURL(flags.URL, routes)
	if err != nil {
		return err
	}
	if session.Authenticated().Discovery.BrowserLoginAvailable == nil || !*session.Authenticated().Discovery.BrowserLoginAvailable {
		return failure.Wrap("enable team browser access", failure.ServerOIDCInvalid, errors.New("team access requires a server with OIDC browser sign-in; configure OIDC before sharing with the team"))
	}
	updated, err := session.Authenticated().Control.SetPreviewTeamAccess(ctx, preview.Id, true)
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
		}{1, preview.Id, "https://" + selected.CanonicalHostname + "/", services, true}))
	}
	return writeHumanFrame(output, "tnl share team create", "shared", "", clioutput.Fields(
		clioutput.Field{Label: "public URL", Value: "https://" + selected.CanonicalHostname + "/"},
	))
}

func runShareTeamRevoke(ctx context.Context, flags teamShareRevokeCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.URL != "" {
		return runExactTeamShare(ctx, flags.selection(), flags.URL, "", true, flags.Output, output, diagnostics)
	}
	if !project.Found() || project.Root == "" {
		return failure.Wrap("select share project", failure.PreviewNotSaved, errors.New("select a configured project to revoke this checkout's team access"))
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl share team revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	id, found, err := session.Store().PreviewID(ctx, current.Team().Id, project.Root)
	if err != nil {
		return err
	}
	if !found {
		return failure.Wrap("read share preview", failure.PreviewNotSaved, errors.New("preview is not saved for this checkout; start a configured app service first"))
	}
	updated, err := session.Authenticated().Control.SetPreviewTeamAccess(ctx, id, false)
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

func runExactTeamShare(ctx context.Context, flags remoteFlags, selector, lifetime string, revoke bool, mode statusOutputMode, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags, "tnl share team", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	return exactTeamShare(ctx, session, selector, lifetime, revoke, mode, output)
}

func exactTeamShare(ctx context.Context, session *clientteam.Session, selector, lifetime string, revoke bool, mode statusOutputMode, output io.Writer) error {
	item, err := resolveVisitorPublicURL(ctx, session, selector)
	if err != nil {
		return err
	}
	var result controlv1.VisitorGrant
	state := "shared"
	if revoke {
		grants, err := session.Authenticated().Control.ListVisitorGrants(ctx, item.Id)
		if err != nil {
			return err
		}
		for _, grant := range grants {
			if string(grant.Kind) == "team" && grant.RevokedAt == nil {
				if err := session.Authenticated().Control.RevokeVisitorGrant(ctx, item.Id, grant.Id); err != nil {
					return err
				}
			}
		}
		state = "revoked"
	} else {
		var expires *time.Time
		if lifetime != "" {
			duration, err := time.ParseDuration(lifetime)
			if err != nil || duration <= 0 {
				return failure.Wrap("validate team grant lifetime", failure.ShareInputInvalid, errors.New("team grant lifetime must be greater than zero"))
			}
			at := time.Now().Add(duration)
			expires = &at
		}
		key, err := randomIdempotencyKey()
		if err != nil {
			return err
		}
		result, err = session.Authenticated().Control.CreateTeamVisitorGrant(ctx, item.Id, key, controlv1.CreateTeamVisitorGrantRequest{ExpiresAt: expires})
		if err != nil {
			return err
		}
	}
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			PublicURLID string                 `json:"public_url_id"`
			Grant       controlv1.VisitorGrant `json:"grant"`
			State       string                 `json:"state"`
		}{item.Id, result, state})
	}
	fields := []clioutput.Field{{Label: "public URL ID", Value: item.Id}, {Label: "hostname", Value: item.CanonicalHostname}}
	return writeHumanFrame(output, "tnl share team", state, "", clioutput.Fields(fields...))
}

func runShareRevoke(ctx context.Context, flags shareRevokeCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, flags.selection(), "tnl share revoke", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	share, err := session.Authenticated().Control.GetShare(ctx, flags.ShareID)
	if err != nil || share.TeamId != current.Team().Id {
		if err != nil {
			return err
		}
		return clientcontrol.ErrNotFound
	}
	if _, err := session.Authenticated().Control.RevokeShare(ctx, share.Id); err != nil {
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
