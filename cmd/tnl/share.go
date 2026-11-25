package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type shareCommand struct {
	Create  shareCheckoutCommand
	Service serviceShareCommand
	Invite  shareInviteCommand
	Link    linkShareCommand
	Token   tokenShareCommand
	Team    teamShareCommand
	List    shareListCommand
	Revoke  shareRevokeCommand
}

type shareLinkOptions struct {
	scopedTeamFlags `embed:""`
	Name            string           `name:"name" help:"Optional label shown when listing this share."`
	ExpiresIn       string           `name:"expires-in" default:"24h" help:"Share lifetime (for example, 24h or 7d; at most 30d)."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type shareCheckoutCommand struct {
	shareLinkOptions `embed:""`
	ServiceName      string `arg:"" name:"service" optional:"" help:"Share only this configured public HTTP service instead of the whole checkout."`
	Service          string `name:"service" help:"Share only this configured public HTTP service instead of the whole checkout."`
}

type teamShareCommand struct {
	Create teamShareCreateCommand
	Revoke teamShareRevokeCommand
}

type teamShareCreateCommand struct {
	ExpiresIn       string `name:"expires-in" help:"Exact URL grant lifetime; omit for perpetual access."`
	scopedTeamFlags `embed:""`
	URL             string           `arg:"" name:"url" optional:"" help:"Public HTTP service name, service ID, hostname, host:port, or HTTPS URL."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type teamShareRevokeCommand struct {
	URL             string `arg:"" optional:"" help:"Exact public URL whose team grants should be revoked; omit for this preview."`
	scopedTeamFlags `embed:""`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type linkShareCommand struct {
	Create shareCreateCommand
}

type shareCreateCommand struct {
	shareLinkOptions `embed:""`
	URL              string `arg:"" name:"url" optional:"" help:"Public HTTP service name, service ID, hostname, host:port, or HTTPS URL."`
	Preview          bool   `name:"preview" help:"Include every current HTTP public URL in this project preview."`
	checkout         bool
	service          string
}

type tokenShareCommand struct {
	Create tokenShareCreateCommand
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
	ShareID         string           `arg:"" name:"share-id" required:"" help:"Exact share ID (shr_) from the creation receipt or share list."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type shareServiceResult struct {
	ServiceID string `json:"service_id"`
	PublicURL string `json:"public_url"`
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

func selectShareService(selector string, routes []controlv1.ServiceSummary) (controlv1.ServiceSummary, error) {
	input, err := parseWholeService(selector, failure.ShareInputInvalid)
	if err != nil {
		return controlv1.ServiceSummary{}, err
	}
	return matchInventory(input, routes, failure.ShareInputInvalid)
}

func previewShares(ctx context.Context, flags remoteFlags, project projectConfiguration, command, service string, diagnostics io.Writer, services map[string]shareServiceResult) (*clientteam.Session, controlv1.Preview, []controlv1.ServiceSummary, error) {
	if !project.Found() || len(project.Config.Services) == 0 {
		return nil, controlv1.Preview{}, nil, failure.Wrap("select share project", failure.PreviewNotSaved, errors.New("select a project with configured services, then start your app"))
	}
	session, err := openTeamSession(ctx, flags, command, diagnostics)
	if err != nil {
		return nil, controlv1.Preview{}, nil, err
	}
	current, err := session.CurrentWithDomains(ctx)
	if err != nil {
		session.Close()
		return nil, controlv1.Preview{}, nil, err
	}
	id, found, err := session.Store().PreviewID(ctx, current.Team().Id, project.LocalWorktreeKey())
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
	names := make([]string, 0, len(project.Config.Services))
	for name, definition := range project.Config.Services {
		if service != "" && name != service {
			continue
		}
		if !checkoutShareEligible(definition) {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	inventory, err := session.Authenticated().Control.ListServices(ctx, current.Team().Id)
	if err != nil {
		session.Close()
		return nil, controlv1.Preview{}, nil, err
	}
	source := project.LocalPublicationIdentity()
	routes := make([]controlv1.ServiceSummary, 0, len(names))
	for _, name := range names {
		effective, err := project.EffectiveService(name)
		if err != nil {
			session.Close()
			return nil, controlv1.Preview{}, nil, err
		}
		expected := controlv1.LocalServiceSource{ProjectKey: source.Key, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(), Service: name}
		var saved controlv1.ServiceSummary
		for _, candidate := range inventory {
			if candidate.TeamId != current.Team().Id || candidate.Source == nil || *candidate.Source != expected {
				continue
			}
			if !opaqueid.Valid(candidate.Id, opaqueid.ServicePrefix) {
				session.Close()
				return nil, controlv1.Preview{}, nil, failure.Wrap("resolve preview services", failure.ServerResponseInvalid, errors.New("server returned an invalid preview service ID"))
			}
			if saved.Id != "" {
				session.Close()
				return nil, controlv1.Preview{}, nil, failure.Wrap("resolve preview services", failure.PreviewStateConflict, fmt.Errorf("service %q has ambiguous source bindings", name))
			}
			saved = candidate
		}
		if saved.Id == "" || saved.Protocol != controlv1.ServiceProtocolHTTP || saved.Endpoint == nil || !saved.Endpoint.Public || !slices.Contains(preview.ServiceIds, saved.Id) ||
			effective.Hostname != nil && saved.Endpoint.Hostname != *effective.Hostname {
			session.Close()
			return nil, controlv1.Preview{}, nil, failure.Wrap("resolve preview services", failure.PreviewStateConflict, fmt.Errorf("service %q is not yet in this preview; start it with its tnl integration", name))
		}
		if effective.Domain != nil {
			domain, err := current.ReadyDomain(*effective.Domain)
			if err != nil {
				session.Close()
				return nil, controlv1.Preview{}, nil, err
			}
			if saved.DomainId == nil || *saved.DomainId != domain.Id {
				session.Close()
				return nil, controlv1.Preview{}, nil, failure.Wrap("resolve preview service domain", failure.PreviewStateConflict, fmt.Errorf("service %q has another saved domain; start it with its tnl integration", name))
			}
		}
		publicURL, err := servicePublicAddress(saved.Protocol, saved.Endpoint)
		if err != nil {
			session.Close()
			return nil, controlv1.Preview{}, nil, err
		}
		routes = append(routes, saved)
		services[name] = shareServiceResult{ServiceID: saved.Id, PublicURL: publicURL}
	}
	return session, preview, routes, nil
}

func runShareCheckout(ctx context.Context, flags shareCheckoutCommand, project projectConfiguration, output, diagnostics io.Writer, correction func(string) []string) error {
	if flags.Service != "" {
		service, found := project.Config.Services[flags.Service]
		if !found || !checkoutShareEligible(service) {
			message := "Select a configured public HTTP service."
			guidance := &commandGuidance{
				error:   failure.Wrap("select share service", failure.ShareInputInvalid, errors.New(message)),
				message: message,
			}
			// do not redirect a correctly spelled private or non-HTTP service
			// to a different public service.
			if !found && correction != nil {
				if candidate := checkoutShareSuggestion(flags.Service, project.Config.Services); candidate != "" {
					guidance.help = correction(candidate)
				}
			}
			return guidance
		}
	}
	return createShare(ctx, shareCreateCommand{
		shareLinkOptions: flags.shareLinkOptions,
		Preview:          flags.Service == "",
		checkout:         true,
		service:          flags.Service,
	}, project, false, output, diagnostics)
}

func checkoutShareEligible(service config.Service) bool {
	return service.Public != nil && *service.Public && config.Protocol(service) == "http"
}

func checkoutShareSuggestion(selected string, services config.Services) string {
	if !naming.ValidServiceName(selected) {
		return ""
	}
	var candidate string
	for name, service := range services {
		if !checkoutShareEligible(service) || !naming.ValidServiceName(name) || !oneServiceNameTypo(selected, name) {
			continue
		}
		if candidate != "" {
			return ""
		}
		candidate = name
	}
	return candidate
}

func oneServiceNameTypo(a, b string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	if len(b)-len(a) > 1 {
		return false
	}
	i := 0
	for i < len(a) && a[i] == b[i] {
		i++
	}
	if len(a) < len(b) {
		return a[i:] == b[i+1:]
	}
	if i == len(a) {
		return false
	}
	return a[i+1:] == b[i+1:] ||
		i+1 < len(a) && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
}

func checkoutShareCorrection(parent *cobra.Command, call commandCall, flags shareCheckoutCommand, name string) []string {
	args := []string{"tnl"}
	if selection := call.project.Selection; selection.Explicit && selection.Path != "" {
		args = append(args, "--config", selection.Path)
	}
	args = append(args, "share")
	useFlag := call.command.Flags().Changed("service")
	for _, sub := range parent.Commands() {
		useFlag = useFlag || sub.Name() == name || slices.Contains(sub.Aliases, name)
	}
	if useFlag {
		args = append(args, "--service")
	}
	args = append(args, name)
	changed := call.command.Flags().Changed
	if changed("expires-in") {
		args = append(args, "--expires-in", flags.ExpiresIn)
	}
	if changed("name") {
		args = append(args, "--name", flags.Name)
	}
	if changed("output") || flags.Output != statusOutputHuman {
		args = append(args, "--output", string(flags.Output))
	}
	if flags.ServerURL != "" {
		server, err := naming.CanonicalControlURL(flags.ServerURL)
		if err != nil {
			return nil
		}
		args = append(args, "--server", server)
	}
	if flags.Team != "" {
		args = append(args, "--team", flags.Team)
	}
	if flags.StateDir != "" {
		args = append(args, "--state-dir", flags.StateDir)
	}
	if noTelemetry, _ := call.command.Flags().GetBool("no-telemetry"); noTelemetry {
		args = append(args, "--no-telemetry")
	}
	return args
}

func checkoutShareEntry(service string, services map[string]shareServiceResult) (string, error) {
	if service != "" {
		if selected, found := services[service]; found {
			return selected.ServiceID, nil
		}
		return "", failure.Wrap("select share service", failure.PreviewNotSaved, errors.New("the selected service has no saved HTTP public URL; start it with its tnl integration"))
	}
	for _, name := range []string{"app", "web"} {
		if selected, found := services[name]; found {
			return selected.ServiceID, nil
		}
	}
	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) == 0 {
		return "", failure.Wrap("select share public URLs", failure.PreviewNotSaved, errors.New("this checkout has no saved HTTP public URLs; start a configured public app service first"))
	}
	return services[names[0]].ServiceID, nil
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
	if flags.checkout {
		command = "tnl share"
	} else if token {
		command = "tnl share token create"
	}
	var session *clientteam.Session
	var preview controlv1.Preview
	var routes []controlv1.ServiceSummary
	var teamID string
	services := make(map[string]shareServiceResult)
	if flags.Preview || flags.URL == "" {
		session, preview, routes, err = previewShares(ctx, flags.selection(), project, command, flags.service, diagnostics, services)
		teamID = preview.TeamId
	} else {
		session, err = openTeamSession(ctx, flags.selection(), command, diagnostics)
		if err == nil {
			current, currentErr := session.Current(ctx)
			if currentErr != nil {
				err = currentErr
			} else {
				teamID = current.Team().Id
				routes, err = session.Authenticated().Control.ListServices(ctx, teamID)
				routes = slices.DeleteFunc(routes, func(service controlv1.ServiceSummary) bool { return service.TeamId != teamID })
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
	if flags.checkout {
		flags.URL, err = checkoutShareEntry(flags.service, services)
		if err != nil {
			return err
		}
	}
	selected, err := selectShareService(flags.URL, routes)
	if err != nil {
		return err
	}
	if selected.Protocol != controlv1.ServiceProtocolHTTP || selected.Endpoint == nil || !selected.Endpoint.Public {
		return failure.Wrap("select share public URL", failure.ShareInputInvalid, errors.New("share links and tokens require an HTTP public URL"))
	}
	ids := []string{selected.Id}
	if flags.Preview {
		ids = anonymousPreviewServiceIDs(routes)
	}
	request := controlv1.CreateShareRequest{
		ServiceIds: ids, EntryServiceId: selected.Id, ExpiresAt: time.Now().UTC().Add(lifetime),
		Label: &flags.Name,
	}
	var previewID *string
	if flags.Preview {
		previewID = &preview.Id
	}
	return createShareCredential(ctx, session.Authenticated().Control, request, previewID, teamID, *selected.Endpoint, token, flags.Output, shareServices(services, flags.Preview), output)
}

func createShareCredential(ctx context.Context, control *clientcontrol.Client, request controlv1.CreateShareRequest, previewID *string, teamID string, endpoint controlv1.ServiceEndpoint, token bool, mode statusOutputMode, services map[string]shareServiceResult, output io.Writer) error {
	publicURL, err := servicePublicAddress(controlv1.ServiceProtocolHTTP, &endpoint)
	if err != nil {
		return err
	}
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		return err
	}
	// control stores share deadlines at microsecond precision.
	request.ExpiresAt = request.ExpiresAt.UTC().Truncate(time.Microsecond)
	var creation controlv1.ShareCreation
	if previewID != nil {
		creation, err = control.CreateShare(ctx, *previewID, key, request)
	} else {
		creation, err = control.CreateServiceShare(ctx, key, request)
	}
	if err != nil {
		return err
	}
	share := creation.Share
	expectedScope := "service"
	if previewID != nil {
		expectedScope = "preview"
	}
	credential := share.Id + "." + creation.TokenSource.Secret
	if !opaqueid.Valid(share.Id, opaqueid.SharePrefix) || share.TeamId != teamID || string(share.Scope) != expectedScope ||
		!slices.Equal(share.ServiceIds, request.ServiceIds) || share.EntryServiceId != request.EntryServiceId || !sameSharePreview(share.PreviewId, previewID) ||
		share.RevokedAt != nil || !share.ExpiresAt.Equal(request.ExpiresAt) || !share.ExpiresAt.After(time.Now()) ||
		creation.TokenSource.Kind != controlv1.VisitorTokenShare || creation.TokenSource.ShareId != share.Id || !serviceShareSecret(credential, share.Id) ||
		creation.Link != publicURL+"/__tnl/share/"+credential {
		return failure.Wrap("create share", failure.ServerResponseInvalid, errors.New("server did not return the requested share and link"))
	}
	if token {
		source, err := json.Marshal(creation.TokenSource)
		if err != nil {
			return err
		}
		scope := controlv1.VisitorResourceScope{Kind: "service", Id: request.EntryServiceId}
		permission, err := control.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: scope, Source: source})
		if err != nil {
			return err
		}
		if permission.Resource != scope || permission.Hostname != endpoint.Hostname || permission.Port != endpoint.Port || permission.VisitorPolicyRevision < 1 || permission.ExpiresAt.After(share.ExpiresAt) || !permission.ExpiresAt.After(time.Now()) || len(permission.VisitorToken) > 2048 || strings.Count(permission.VisitorToken, ".") != 2 {
			return failure.Wrap("prepare share token", failure.ServerResponseInvalid, errors.New("server returned a different public URL scope or invalid permission"))
		}
		if mode == statusOutputJSON {
			return failure.Wrap("write share token", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
				SchemaVersion int       `json:"schema_version"`
				ShareID       string    `json:"share_id"`
				ShareToken    string    `json:"share_token"`
				ServiceID     string    `json:"service_id"`
				ExpiresAt     time.Time `json:"expires_at"`
			}{1, share.Id, permission.VisitorToken, request.EntryServiceId, permission.ExpiresAt}))
		}
		_, err = fmt.Fprintln(output, permission.VisitorToken)
		return failure.Wrap("write share token", failure.OutputUnavailable, err)
	}
	entry := creation.Link
	if mode == statusOutputJSON {
		return failure.Wrap("write share URL", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion int                           `json:"schema_version"`
			ShareID       string                        `json:"share_id"`
			PreviewID     *string                       `json:"preview_id,omitempty"`
			EntryURL      string                        `json:"entry_url"`
			ServiceIDs    []string                      `json:"service_ids"`
			Services      map[string]shareServiceResult `json:"services,omitempty"`
			ExpiresAt     time.Time                     `json:"expires_at"`
		}{1, share.Id, share.PreviewId, entry, share.ServiceIds, services, share.ExpiresAt}))
	}
	_, err = fmt.Fprintln(output, entry)
	return failure.Wrap("write share URL", failure.OutputUnavailable, err)
}

func sameSharePreview(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func anonymousPreviewServiceIDs(routes []controlv1.ServiceSummary) []string {
	ids := make([]string, 0, len(routes))
	for _, service := range routes {
		if service.Protocol == controlv1.ServiceProtocolHTTP && service.Endpoint != nil && service.Endpoint.Public {
			ids = append(ids, service.Id)
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
	rows := make([][]string, 0, len(shares))
	teamGrant := false
	if project.Found() && project.Root != "" {
		id, found, err := session.Store().PreviewID(ctx, current.Team().Id, project.LocalWorktreeKey())
		if err != nil {
			return err
		}
		if found {
			preview, err := session.Authenticated().Control.GetPreview(ctx, id)
			if err != nil {
				return err
			}
			if preview.TeamId == current.Team().Id && preview.TeamAccessEnabled != nil && *preview.TeamAccessEnabled {
				teamGrant = true
				rows = append(rows, []string{"team", "active", "never", "-", "this preview", strconv.Itoa(len(preview.ServiceIds))})
			}
		}
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write share list", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion     int               `json:"schema_version"`
			Shares            []controlv1.Share `json:"shares"`
			TeamAccessEnabled bool              `json:"team_access_enabled"`
		}{1, shares, teamGrant}))
	}
	now := time.Now()
	for _, share := range shares {
		rows = append(rows, append(shareRow(share, now), strconv.Itoa(len(share.ServiceIds))))
	}
	return writeResult(output, clioutput.Table([]string{"ACCESS", "STATE", "EXPIRES", "ID", "NAME", "SERVICES"}, rows, "No shares."))
}

func runExactShareList(ctx context.Context, flags remoteFlags, selector string, mode statusOutputMode, output, diagnostics io.Writer) error {
	s, err := openTeamSession(ctx, flags, "tnl share list", diagnostics)
	if err != nil {
		return err
	}
	defer s.Close()
	item, err := resolveManagedService(ctx, s, selector)
	if err != nil {
		return err
	}
	grants, err := s.Authenticated().Control.ListServiceGrants(ctx, item.Id)
	if err != nil {
		return err
	}
	invitations, err := s.Authenticated().Control.ListServiceInvitations(ctx, item.Id)
	if err != nil {
		return err
	}
	shares, err := s.Authenticated().Control.ListTeamShares(ctx, item.TeamId)
	if err != nil {
		return err
	}
	shares = slices.DeleteFunc(shares, func(share controlv1.Share) bool { return !slices.Contains(share.ServiceIds, item.Id) })
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			Grants      []controlv1.ServiceGrant      `json:"grants"`
			Invitations []controlv1.ServiceInvitation `json:"invitations"`
			Shares      []controlv1.Share             `json:"shares"`
		}{grants, invitations, shares})
	}
	rows := make([][]string, 0, len(grants)+len(invitations)+len(shares))
	now := time.Now()
	for _, grant := range grants {
		rows = append(rows, shareGrantRow(grant, now))
	}
	for _, invitation := range invitations {
		rows = append(rows, shareInviteRow(invitation, now))
	}
	for _, share := range shares {
		rows = append(rows, shareRow(share, now))
	}
	return writeShareRows(output, item.Id, rows)
}

func runShareTeamCreate(ctx context.Context, flags teamShareCreateCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.URL != "" {
		return runExactTeamShare(ctx, flags.selection(), flags.URL, flags.ExpiresIn, false, flags.Output, output, diagnostics)
	}
	if flags.ExpiresIn != "" {
		return failure.Wrap("select expiring team grant", failure.ShareInputInvalid, errors.New("an expiring team grant requires an exact public URL"))
	}
	services := make(map[string]shareServiceResult)
	session, preview, routes, err := previewShares(ctx, flags.selection(), project, "tnl share team create", "", diagnostics, services)
	if err != nil {
		return err
	}
	defer session.Close()
	entry, err := checkoutShareEntry("", services)
	if err != nil {
		return err
	}
	selected, err := selectShareService(entry, routes)
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
		}{1, preview.Id, "https://" + selected.Endpoint.Hostname + "/", services, true}))
	}
	return writeResult(output, clioutput.Literal("https://"+selected.Endpoint.Hostname+"/"),
		clioutput.Text("Team members can sign in to visit this preview."))
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
	id, found, err := session.Store().PreviewID(ctx, current.Team().Id, project.LocalWorktreeKey())
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
	return writeResult(output, clioutput.Line("Revoked team access to preview "+id))
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
	item, err := resolveManagedService(ctx, session, selector)
	if err != nil {
		return err
	}
	var result controlv1.ServiceGrant
	state := "shared"
	if revoke {
		grants, err := session.Authenticated().Control.ListServiceGrants(ctx, item.Id)
		if err != nil {
			return err
		}
		for _, grant := range grants {
			if string(grant.Kind) == "team" && grant.RevokedAt == nil {
				if err := session.Authenticated().Control.RevokeServiceGrant(ctx, item.Id, grant.Id); err != nil {
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
			at := time.Now().UTC().Add(duration).Truncate(time.Microsecond)
			expires = &at
		}
		key, err := randomIdempotencyKey()
		if err != nil {
			return err
		}
		result, err = session.Authenticated().Control.CreateServiceGrant(ctx, item.Id, key, controlv1.CreateServiceGrantRequest{Kind: "team", ExpiresAt: expires})
		if err != nil {
			return err
		}
		if !validServiceShareGrant(result, item.Id) || result.Kind != "team" || result.IdentityId != nil || result.InvitationId != nil || (result.ExpiresAt == nil) != (expires == nil) || expires != nil && !result.ExpiresAt.Equal(*expires) {
			return serviceShareResponse()
		}
	}
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			ServiceID string                 `json:"service_id"`
			Grant     controlv1.ServiceGrant `json:"grant"`
			State     string                 `json:"state"`
		}{item.Id, result, state})
	}
	address := item.Id
	if item.Endpoint != nil && item.Endpoint.Public {
		if endpoint, err := servicePublicAddress(item.Protocol, item.Endpoint); err == nil {
			address = endpoint
		}
	}
	if revoke {
		return writeResult(output, clioutput.Line("Revoked team access to "+address))
	}
	grant := "Team access granted."
	if result.ExpiresAt != nil {
		grant = "Team access granted until " + shareExpiry(*result.ExpiresAt) + "."
	}
	return writeResult(output, clioutput.Line(address), clioutput.Text(grant))
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
	if err != nil {
		return err
	}
	if share.Id != flags.ShareID {
		return failure.Wrap("read share", failure.ServerResponseInvalid, errors.New("server returned a different share ID"))
	}
	if share.TeamId != current.Team().Id {
		return clientcontrol.ErrNotFound
	}
	revoked, err := session.Authenticated().Control.RevokeShare(ctx, flags.ShareID)
	if err != nil {
		return err
	}
	if revoked.Id != flags.ShareID || revoked.TeamId != share.TeamId || revoked.RevokedAt == nil || revoked.RevokedAt.IsZero() ||
		revoked.Scope != share.Scope || !sameSharePreview(revoked.PreviewId, share.PreviewId) ||
		revoked.EntryServiceId != share.EntryServiceId || !slices.Equal(revoked.ServiceIds, share.ServiceIds) {
		return failure.Wrap("revoke share", failure.ServerResponseInvalid, errors.New("server did not confirm revocation of the selected share"))
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write share revocation", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			ShareID       string `json:"share_id"`
			Revoked       bool   `json:"revoked"`
		}{1, revoked.Id, true}))
	}
	return writeResult(output, clioutput.Line("Revoked share "+revoked.Id))
}

func (a *commandApp) newShareCommand() *cobra.Command {
	f := a.flags
	cShare := &cobra.Command{
		Use: "share", Short: "Create a share link for this checkout's preview.", GroupID: "access",
		Long: "Print one link to this checkout's current public HTTP services. It expires after 24 hours by default. Pass a service name or use --service to include just one service. Use --output=json to get the link and its share ID together. Pass that ID to tnl share revoke to end access early. To select by service ID or address, use tnl share link create.",
	}
	cShareCreate := &cobra.Command{Use: "create", Short: "Print a share link for this checkout; create is optional."}
	a.leaf(cShareCreate, &f.Share.Create, func(call commandCall) error {
		return runShareCheckout(call.ctx, f.Share.Create, call.project, a.out, a.errOut, func(name string) []string {
			return checkoutShareCorrection(cShare, call, f.Share.Create, name)
		})
	})
	useProjectServiceArgument(cShareCreate, &f.Share.Create.ServiceName, &f.Share.Create.Service, failure.ShareInputInvalid)
	cShare.AddCommand(cShareCreate)
	a.useDefault(cShare, cShareCreate)
	cShareService := &cobra.Command{Use: "service", Short: "Share one service by its configured name or service ID."}
	cShareServiceInvite := &cobra.Command{Use: "invite", Short: "Invite someone to one service by verified email."}
	cShareServiceInviteCreate := &cobra.Command{
		Use: "create", Short: "Print a one-use invitation for the recipient.",
		Long: "Invite the recipient to this service without adding them to your team. Set an expiry of at most 30 days with --expires-at or --expires-in.",
	}
	a.leaf(cShareServiceInviteCreate, &f.Share.Service.Invite.Create, func(call commandCall) error {
		return runServiceShareInviteCreate(call.ctx, f.Share.Service.Invite.Create, call.project, a.out, a.errOut)
	})
	cShareServiceInvite.AddCommand(cShareServiceInviteCreate)
	cShareServiceInviteAccept := &cobra.Command{Use: "accept", Short: "Accept an invitation using the recipient's verified email."}
	a.leaf(cShareServiceInviteAccept, &f.Share.Service.Invite.Accept, func(call commandCall) error {
		return runServiceShareInviteAccept(call.ctx, f.Share.Service.Invite.Accept, a.out, a.errOut)
	})
	cShareServiceInvite.AddCommand(cShareServiceInviteAccept)
	cShareService.AddCommand(cShareServiceInvite)
	cShareServiceList := &cobra.Command{Use: "list", Short: "List service grants, invitations, and shares, including expired and revoked entries."}
	a.leaf(cShareServiceList, &f.Share.Service.List, func(call commandCall) error {
		return runServiceShareList(call.ctx, f.Share.Service.List, call.project, a.out, a.errOut)
	})
	cShareService.AddCommand(cShareServiceList)
	cShareServiceRevoke := &cobra.Command{Use: "revoke", Short: "Revoke one invitation, identity grant, HTTP credential, or exact service share."}
	a.leaf(cShareServiceRevoke, &f.Share.Service.Revoke, func(call commandCall) error {
		return runServiceShareRevoke(call.ctx, f.Share.Service.Revoke, call.project, a.out, a.errOut)
	})
	cShareService.AddCommand(cShareServiceRevoke)
	cShareServiceLink := &cobra.Command{Use: "link", Short: "Create a browser link to one public HTTP service."}
	cShareServiceLinkCreate := &cobra.Command{Use: "create", Short: "Print a share link that expires in at most 7 days."}
	a.leaf(cShareServiceLinkCreate, &f.Share.Service.Link.Create, func(call commandCall) error {
		return runServiceShareHTTPCreate(call.ctx, f.Share.Service.Link.Create, call.project, false, a.out, a.errOut)
	})
	cShareServiceLink.AddCommand(cShareServiceLinkCreate)
	cShareService.AddCommand(cShareServiceLink)
	cShareServiceToken := &cobra.Command{Use: "token", Short: "Give an HTTP client access to one public HTTP service."}
	cShareServiceTokenCreate := &cobra.Command{
		Use: "create", Short: "Print a short-lived Tnl-Visitor-Token for one service.",
		Long: "Set the share's expiry with --expires-in or --expires-at (at most 7 days). The printed token expires after at most 5 minutes, or sooner if the share expires.",
	}
	a.leaf(cShareServiceTokenCreate, &f.Share.Service.Token.Create, func(call commandCall) error {
		return runServiceShareHTTPCreate(call.ctx, f.Share.Service.Token.Create, call.project, true, a.out, a.errOut)
	})
	cShareServiceToken.AddCommand(cShareServiceTokenCreate)
	cShareService.AddCommand(cShareServiceToken)
	cShare.AddCommand(cShareService)
	cShareInvite := &cobra.Command{Use: "invite", Short: "Invite a verified-email visitor without team membership."}
	cShareInviteCreate := &cobra.Command{Use: "create", Short: "Print an invitation for one email address and public URL."}
	a.leaf(cShareInviteCreate, &f.Share.Invite.Create, func(call commandCall) error {
		return runShareInviteCreate(call.ctx, f.Share.Invite.Create, a.out, a.errOut)
	})
	cShareInvite.AddCommand(cShareInviteCreate)
	cShareInviteAccept := &cobra.Command{Use: "accept", Short: "Accept an invitation using the recipient's verified email."}
	a.leaf(cShareInviteAccept, &f.Share.Invite.Accept, func(call commandCall) error {
		return runShareInviteAccept(call.ctx, f.Share.Invite.Accept, a.out, a.errOut)
	})
	cShareInvite.AddCommand(cShareInviteAccept)
	cShareInviteList := &cobra.Command{Use: "list", Short: "List visitor invitations for one public URL."}
	a.leaf(cShareInviteList, &f.Share.Invite.List, func(call commandCall) error {
		return runShareInviteList(call.ctx, f.Share.Invite.List, a.out, a.errOut)
	})
	cShareInvite.AddCommand(cShareInviteList)
	cShareInviteRevoke := &cobra.Command{Use: "revoke", Short: "Revoke a visitor invitation by ID."}
	a.leaf(cShareInviteRevoke, &f.Share.Invite.Revoke, func(call commandCall) error {
		return runShareInviteRevoke(call.ctx, f.Share.Invite.Revoke, a.out, a.errOut)
	})
	cShareInvite.AddCommand(cShareInviteRevoke)
	cShare.AddCommand(cShareInvite)
	cShareLink := &cobra.Command{Use: "link", Short: "Create a browser share link."}
	cShareLinkCreate := &cobra.Command{Use: "create", Short: "Create a link for one public URL, or --preview for this preview."}
	a.leaf(cShareLinkCreate, &f.Share.Link.Create, func(call commandCall) error {
		return runShareCreate(call.ctx, f.Share.Link.Create, call.project, a.out, a.errOut)
	})
	requireWholeServiceArgument(cShareLinkCreate, 0, failure.ShareInputInvalid)
	cShareLink.AddCommand(cShareLinkCreate)
	cShare.AddCommand(cShareLink)
	cShareToken := &cobra.Command{Use: "token", Short: "Create a share token for an HTTP client."}
	cShareTokenCreate := &cobra.Command{
		Use: "create", Short: "Print a visitor token for one public URL.",
		Long: "Print a token for the Tnl-Visitor-Token HTTP header. The token lasts at most five minutes. --expires-in sets the lifetime of the underlying share.",
	}
	a.leaf(cShareTokenCreate, &f.Share.Token.Create, func(call commandCall) error {
		return runShareTokenCreate(call.ctx, f.Share.Token.Create, call.project, a.out, a.errOut)
	})
	requireWholeServiceArgument(cShareTokenCreate, 0, failure.ShareInputInvalid)
	cShareTokenCreate.Flags().Lookup("preview").Hidden = true
	cShareTokenCreate.Flags().Lookup("name").Usage = "Required. Identify the automation using this token."
	cShareToken.AddCommand(cShareTokenCreate)
	cShare.AddCommand(cShareToken)
	cShareTeam := &cobra.Command{Use: "team", Short: "Manage team access to a preview or one public URL."}
	cShareTeamCreate := &cobra.Command{Use: "create", Short: "Let current team members visit this preview or URL."}
	a.leaf(cShareTeamCreate, &f.Share.Team.Create, func(call commandCall) error {
		return runShareTeamCreate(call.ctx, f.Share.Team.Create, call.project, a.out, a.errOut)
	})
	requireWholeServiceArgument(cShareTeamCreate, 0, failure.ShareInputInvalid)
	cShareTeam.AddCommand(cShareTeamCreate)
	cShareTeamRevoke := &cobra.Command{Use: "revoke", Short: "Revoke team access to this preview or URL."}
	a.leaf(cShareTeamRevoke, &f.Share.Team.Revoke, func(call commandCall) error {
		return runShareTeamRevoke(call.ctx, f.Share.Team.Revoke, call.project, a.out, a.errOut)
	})
	requireWholeServiceArgument(cShareTeamRevoke, 0, failure.ShareInputInvalid)
	cShareTeam.AddCommand(cShareTeamRevoke)
	cShare.AddCommand(cShareTeam)
	cShareList := &cobra.Command{Use: "list", Short: "List access for the selected team."}
	a.leaf(cShareList, &f.Share.List, func(call commandCall) error {
		return runShareList(call.ctx, f.Share.List, call.project, a.out, a.errOut)
	})
	cShare.AddCommand(cShareList)
	cShareRevoke := &cobra.Command{Use: "revoke", Short: "Revoke a share by ID."}
	a.leaf(cShareRevoke, &f.Share.Revoke, func(call commandCall) error {
		return runShareRevoke(call.ctx, f.Share.Revoke, a.out, a.errOut)
	})
	bindRevoke := cShareRevoke.Args
	cShareRevoke.Args = func(cmd *cobra.Command, args []string) error {
		if err := bindRevoke(cmd, args); err != nil {
			return err
		}
		if !opaqueid.Valid(f.Share.Revoke.ShareID, opaqueid.SharePrefix) {
			const message = "Pass an exact share ID (shr_), not a share link. Use the receipt or tnl share list to find it."
			return &commandGuidance{error: failure.Wrap("select share", failure.ShareInputInvalid, errors.New("invalid share ID")), message: message}
		}
		return nil
	}
	cShare.AddCommand(cShareRevoke)
	return cShare
}
