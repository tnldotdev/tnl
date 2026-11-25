package main

import (
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func writeStatus(output io.Writer, flags statusCommand, projects []projectStatus) error {
	if len(projects) == 0 {
		return writeResult(output, clioutput.Text("No projects recorded locally."))
	}
	var blocks, notices, warnings []clioutput.Block
	var services, integrations, webhooks, aliases statusRows
	type integrationIssue struct{ reason, action string }
	var issues []integrationIssue
	affected := map[integrationIssue][]string{}
	serverOrigins := []string{}
	servers := map[string]*serverStatusView{}
	var projectLabels map[string]string
	if flags.All {
		projectLabels = shortProjectLabels(projects)
	}
	for _, project := range projects {
		label := ""
		if flags.All {
			label = projectLabels[project.Project]
		}
		var localRows []statusPublication
		if local := project.Local; local != nil {
			note := func(name, state string, reason failure.Reason, action string) {
				if state == "ready" || reason == "" && action == "" {
					return
				}
				if label != "" {
					name = label + "/" + name
				}
				issue := integrationIssue{statusError(string(reason)), action}
				if _, exists := affected[issue]; !exists {
					issues = append(issues, issue)
				}
				affected[issue] = append(affected[issue], name)
			}
			if !local.Available && local.readErr == nil {
				warnings = append(warnings, statusNotice(label, "Local status unavailable."))
			}
			for _, entry := range snapshotObservations(local.Snapshot.Services, local.Tunnels.Tunnels) {
				item := publicationStatus(entry, local.CheckedAt)
				localRows = append(localRows, item)
			}
			for _, u := range local.Tunnels.IntegrationURLs {
				integrations.add(label, u.Kind, u.State, u.PublicURL)
				note(u.Kind, u.State, u.Reason, u.Action)
				for _, e := range u.Endpoints {
					webhooks.add(label, e.Name, e.Service, e.State, e.URL)
					note("webhook "+e.Name, e.State, e.Reason, e.Action)
				}
			}
			for _, a := range local.Tunnels.Aliases {
				aliases.add(label, a.Name, a.Service, a.State, a.PublicURL, a.SelectedProject)
				note("alias "+a.Name, a.State, a.Reason, a.Action)
			}
			if local.Available && len(localRows)+len(local.Tunnels.IntegrationURLs)+len(local.Tunnels.Aliases) == 0 {
				message := "No local publications."
				switch deployment := config.SelectedDeployment(flags.Configuration.Config); {
				case !flags.All && deployment != "local":
					message = "Deployment " + deployment + " is remote. No local publications."
				case flags.Service != "":
					message = "No local publication for " + flags.Service + "."
				}
				notices = append(notices, statusNotice(label, message))
			}
		}
		if server := project.Server; server != nil {
			view := servers[server.ControlURL]
			if view == nil {
				view = &serverStatusView{}
				servers[server.ControlURL] = view
				serverOrigins = append(serverOrigins, server.ControlURL)
			}
			view.collect(project, flags, label, localRows)
		}
		for _, item := range localRows {
			if flags.Service != "" && !flags.All {
				blocks = appendStatusSection(blocks, item.detail(flags)...)
			} else {
				services.add(label, item.name, item.ready, statusValue(item.url))
			}
		}
	}
	blocks = services.appendTable(blocks, flags.All, "SERVICE", "READY", "URL")
	blocks = integrations.appendTable(blocks, flags.All, "INTEGRATION", "STATE", "URL")
	blocks = webhooks.appendTable(blocks, flags.All, "WEBHOOK", "SERVICE", "STATE", "URL")
	blocks = aliases.appendTable(blocks, flags.All, "ALIAS", "SERVICE", "STATE", "URL", "SELECTED WORKTREE")
	for _, issue := range issues {
		text := strings.Join(affected[issue], ", ") + ":"
		if issue.reason != "" {
			text += " " + issue.reason
		}
		blocks = appendStatusSection(blocks, clioutput.Text(text))
		if issue.action != "" {
			blocks = append(blocks, clioutput.Line(issue.action))
		}
	}
	blocks = appendStatusSection(blocks, notices...)
	for _, origin := range serverOrigins {
		view := servers[origin]
		blocks = appendStatusSection(blocks, view.blocks(origin, flags.All)...)
		warnings = append(warnings, view.warnings...)
	}
	if err := writeResult(output, blocks...); err != nil {
		return err
	}
	if len(warnings) != 0 && flags.diagnostics != nil {
		return writeResult(flags.diagnostics, warnings...)
	}
	return nil
}

// use the shortest unique trailing path, including when several worktrees
// have the same checkout directory name.
func shortProjectLabels(projects []projectStatus) map[string]string {
	suffixes := make(map[string][]string, len(projects))
	count := map[string]int{}
	for _, project := range projects {
		path := filepath.Clean(project.Project)
		for i := 0; ; {
			suffixes[project.Project] = append(suffixes[project.Project], path[i:])
			count[path[i:]]++
			next := strings.IndexByte(path[i:], filepath.Separator)
			if next < 0 || i+next+1 == len(path) {
				break
			}
			i += next + 1
		}
	}
	labels := make(map[string]string, len(projects))
	for path, names := range suffixes {
		for _, name := range names {
			if count[name] == 1 {
				labels[path] = name
			}
		}
	}
	return labels
}

func statusNotice(project, message string) clioutput.Block {
	if project != "" {
		message = project + ": " + message
	}
	return clioutput.Text(message)
}

func appendStatusSection(blocks []clioutput.Block, section ...clioutput.Block) []clioutput.Block {
	if len(section) == 0 {
		return blocks
	}
	if len(blocks) != 0 {
		blocks = append(blocks, clioutput.Line(""))
	}
	return append(blocks, section...)
}

type statusRows [][]string

func (rows *statusRows) add(project string, cells ...string) {
	if project != "" {
		cells = append([]string{project}, cells...)
	}
	*rows = append(*rows, cells)
}

func (rows statusRows) appendTable(blocks []clioutput.Block, all bool, columns ...string) []clioutput.Block {
	if len(rows) == 0 {
		return blocks
	}
	if all {
		columns = append([]string{"PROJECT"}, columns...)
	}
	return appendStatusSection(blocks, clioutput.Table(columns, rows, ""))
}

func statusValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

type statusPublication struct {
	snapshotObservation
	name, ready, url, lastError, lastSeen, server string
	confirmed                                     bool
	serverFields                                  []clioutput.Field
}

func publicationStatus(entry snapshotObservation, at time.Time) statusPublication {
	item := statusPublication{snapshotObservation: entry, ready: "Unknown"}
	s, t := entry.service, entry.tunnel
	if t != nil {
		item.name, item.url = observationName(t.Service), t.PublicURL
		item.lastError = statusError(t.Failure)
	}
	if s != nil {
		item.name = observationName(s.Name)
		if s.PublicURL != "" {
			item.url = s.PublicURL
		}
		if s.Failure != "" {
			item.lastError = statusError(s.Failure)
		}
	}
	if t != nil && t.State == clientstate.TunnelStateStale {
		item.ready, item.lastError = "Unknown (stale)", ""
		if !t.HeartbeatAt.IsZero() && !at.Before(t.HeartbeatAt) {
			item.lastSeen = statusAge(at.Sub(t.HeartbeatAt))
		}
		return item
	}
	if s == nil || !s.Registered || !s.Routable || s.Failure == "runtime.manager_unavailable" {
		return item
	}
	if t == nil && s.TunnelID != "" || t != nil && (t.State != clientstate.TunnelStateReady || t.PublishRunNumber != s.RunNumber || t.PublicURL != s.PublicURL) {
		return item
	}
	o := s.Observation
	if o == nil || o.CheckedAt.IsZero() || s.RegistrationID == "" || o.RegistrationID != s.RegistrationID ||
		s.RunNumber == 0 || o.RunNumber != s.RunNumber || o.Readiness != s.Readiness || (o.Target != "" && o.Target != s.Target) {
		return item
	}
	if o.Reason == "runtime.target_changed" {
		item.lastError = statusError(o.Reason)
		return item
	}
	if o.Ready != s.Ready || o.Ready && (o.Reason != "" || o.Status != 0 && (o.Status < 200 || o.Status >= 300)) {
		return item
	}
	if s.Ready {
		item.ready, item.lastError = "Yes", ""
		item.confirmed = true
	} else if o.Status != 0 || o.Reason != "" {
		item.ready = "No"
		item.lastError = statusError(o.Reason)
		if o.Status != 0 {
			item.ready = "No (HTTP " + strconv.Itoa(o.Status) + ")"
			item.lastError = ""
		}
	} else {
		return item
	}
	if s.PublicURL == "" || (s.ServiceProtocol != "" && s.ServiceProtocol != "http") {
		item.ready += " (target only)"
	}
	return item
}

func statusAge(age time.Duration) string {
	switch {
	case age >= 24*time.Hour:
		return countState(int(age/(24*time.Hour)), "day", "days") + " ago"
	case age >= time.Hour:
		return countState(int(age/time.Hour), "hour", "hours") + " ago"
	case age >= time.Minute:
		return countState(int(age/time.Minute), "minute", "minutes") + " ago"
	default:
		return "less than a minute ago"
	}
}

func statusError(code string) string {
	if code == string(failure.ServerResponseInvalid) {
		return "The server returned an unexpected response."
	}
	return observationError(code)
}

func (item statusPublication) detail(flags statusCommand) []clioutput.Block {
	fields := []clioutput.Field{{Label: "Service", Value: item.name}, {Label: "URL", Value: statusValue(item.url)}, {Label: "Ready", Value: item.ready}}
	if item.lastSeen != "" {
		fields = append(fields, clioutput.Field{Label: "Last seen", Value: item.lastSeen})
	}
	if item.lastError != "" {
		fields = append(fields, clioutput.Field{Label: "Last error", Value: item.lastError, Prose: true})
	}
	if item.server != "" {
		fields = append(fields, clioutput.Field{Label: "Server", Value: item.server})
	}
	fields = append(fields, item.serverFields...)
	blocks := []clioutput.Block{clioutput.Fields(fields...)}
	if _, ok := flags.Configuration.Config.Services[item.key]; !item.confirmed && item.service != nil && ok && config.SelectedDeployment(flags.Configuration.Config) == "local" {
		cmd := (commandScope{configArgs: flags.configArgs, stateDir: flags.StateDir}).command("wait", "--service", item.key)
		blocks = appendStatusSection(blocks, clioutput.Section("Check readiness", clioutput.Literal(cmd)))
	}
	return blocks
}

type serverStatusView struct {
	services, bindings, members statusRows
	details, notices, warnings  []clioutput.Block
}

func (view *serverStatusView) collect(project projectStatus, flags statusCommand, label string, local []statusPublication) {
	server := project.Server
	detail := flags.Service != "" && !flags.All
	reason := server.Reason
	if server.inventoryReason != "" {
		reason = server.inventoryReason
	}
	warn := func(message string) {
		if server.ControlURL != "" {
			message += " (" + server.ControlURL + ")"
		}
		view.warnings = append(view.warnings, statusNotice(label, message))
	}
	switch {
	case reason == "no local service IDs for this project":
		if (project.Local == nil || !project.Local.Available) && server.Applied == nil && len(server.AppliedServices) == 0 {
			view.notices = append(view.notices, statusNotice(label, "No saved services to look up on the server."))
		}
	case reason != "":
		warn("Server status unavailable: " + reason)
	case !server.Available:
		warn("Server status unavailable.")
	}
	services, protocols := server.AppliedServices, server.declarations
	if applied := server.Applied; applied != nil {
		services, protocols = applied.Services, applied.ServiceDeclarations
	}
	joined := make(map[int]bool)
	for _, s := range server.Services {
		name := s.Name
		if s.sourceName != "" {
			name = s.sourceName
		}
		state, publisher := "disabled", "none reported"
		if s.Enabled {
			state = "enabled"
		}
		if s.PublisherObservation == "ready_publisher_hint" {
			publisher = "reported"
		}
		address, _ := servicePublicAddress(s.Protocol, s.Endpoint)
		access, reserved := statusAccess(s.Protocol, s.Endpoint)
		fields := []clioutput.Field{{Label: "State", Value: state}, {Label: "Protocol", Value: string(s.Protocol)}, {Label: "Access", Value: access}, {Label: "Publisher", Value: publisher}}
		if detail && name != s.Name {
			fields = append(fields, clioutput.Field{Label: "Saved name", Value: s.Name})
		}
		if reserved != "" {
			fields = append(fields, clioutput.Field{Label: "Reserved port", Value: reserved})
		}
		if detail {
			for i, binding := range services {
				if sameSavedBinding(s, binding, protocols[binding.Service]) {
					fields = append(fields, clioutput.Field{Label: "Deployment", Value: binding.Deployment})
					if binding.Service != name {
						fields = append(fields, clioutput.Field{Label: "Project service", Value: binding.Service})
					}
					joined[i] = true
				}
			}
		}
		if i := slices.IndexFunc(local, func(p statusPublication) bool { return p.matchesInventory(server.ControlURL, s, address) }); i >= 0 {
			if detail {
				local[i].server = server.ControlURL
				local[i].serverFields = append(local[i].serverFields, fields...)
				continue
			}
			if s.Enabled && local[i].tunnel.State == clientstate.TunnelStateReady {
				continue
			}
		}
		if detail {
			view.addDetail(name, address, fields...)
		} else {
			view.services.add(label, name, state, string(s.Protocol), access, statusValue(address))
		}
	}
	if applied := server.Applied; applied != nil {
		if applied.RetiredAt != nil {
			view.notices = append(view.notices, statusNotice(label, "Deployment "+applied.Deployment+": retired"))
		}
		for _, member := range applied.Members {
			health := "not healthy"
			if member.Healthy {
				health = "healthy"
			}
			if member.Runtime != nil && !member.Runtime.Active {
				health += ", last observed process offline"
			}
			instance := "-"
			if member.Runtime != nil && member.Runtime.Deployment != nil && member.Runtime.Deployment.Report.Instance != "" {
				instance = member.Runtime.Deployment.Report.Instance
			}
			view.members.add(label, member.DeploymentName, instance, health)
		}
	}
	for i, binding := range services {
		if joined[i] {
			continue
		}
		protocol := protocols[binding.Service]
		address, access, reserved := bindingEndpoint(binding, protocol)
		deployment := clioutput.Field{Label: "Deployment", Value: binding.Deployment}
		if binding.Deployment == "local" {
			if i := slices.IndexFunc(local, func(p statusPublication) bool {
				return p.matchesBinding(project.Project, server.ControlURL, binding, protocol, address)
			}); i >= 0 {
				if detail {
					local[i].server = server.ControlURL
					if binding.ServiceId != nil && len(local[i].serverFields) == 0 {
						local[i].serverFields = append(local[i].serverFields, clioutput.Field{Label: "Access", Value: access})
					}
					local[i].serverFields = append(local[i].serverFields, deployment)
				}
				continue
			}
		}
		if detail {
			fields := []clioutput.Field{deployment, {Label: "Access", Value: access}}
			if reserved != "" {
				fields = append(fields, clioutput.Field{Label: "Reserved port", Value: reserved})
			}
			view.addDetail(binding.Service, address, fields...)
		} else {
			view.bindings.add(label, binding.Service, binding.Deployment, access, statusValue(address))
		}
	}
	if server.AppliedReason != "" && server.AppliedReason != reason {
		warn("Applied configuration: " + server.AppliedReason)
	}
	if reason == "" && server.Available && server.AppliedReason == "" && len(server.Services)+len(services) == 0 &&
		(flags.Service != "" || project.Local == nil || !project.Local.Available) {
		message := "No server service records."
		if flags.Service != "" {
			message = "No server record for " + flags.Service + "."
		}
		view.notices = append(view.notices, statusNotice(label, message))
	}
}

func (view *serverStatusView) blocks(origin string, all bool) []clioutput.Block {
	blocks := view.services.appendTable(view.details, all, "SERVICE", "STATE", "PROTOCOL", "ACCESS", "ADDRESS")
	blocks = view.bindings.appendTable(blocks, all, "SERVICE", "DEPLOYMENT", "ACCESS", "ADDRESS")
	blocks = view.members.appendTable(blocks, all, "DEPLOYMENT", "PUBLISHER INSTANCE", "HEALTH")
	blocks = appendStatusSection(blocks, view.notices...)
	if len(blocks) != 0 && origin != "" {
		blocks = append([]clioutput.Block{clioutput.Line("Server: " + origin)}, blocks...)
	}
	return blocks
}

func bindingEndpoint(binding controlv1.AppliedProjectService, protocol controlv1.ServiceProtocol) (address, access, reserved string) {
	if binding.Public == nil && (binding.ServiceKind != "service" || binding.ServiceId == nil) {
		return "", "not reported", ""
	}
	endpoint := controlv1.ServiceEndpoint{Public: binding.Public != nil && *binding.Public}
	if binding.Port != nil {
		endpoint.Port = *binding.Port
	}
	if binding.Hostname != nil {
		endpoint.Hostname = *binding.Hostname
	}
	if endpoint.Public && binding.Port != nil && binding.Hostname != nil {
		address, _ = servicePublicAddress(protocol, &endpoint)
		if address == "" {
			address = endpoint.Hostname + ":" + strconv.Itoa(endpoint.Port)
		}
	}
	access, reserved = statusAccess(protocol, &endpoint)
	return address, access, reserved
}

func sameSavedBinding(s statusServerService, b controlv1.AppliedProjectService, protocol controlv1.ServiceProtocol) bool {
	if b.ServiceId == nil || *b.ServiceId == "" || *b.ServiceId != s.ServiceID || b.ServiceKind != "service" || s.Protocol != protocol ||
		b.Hostname == nil || s.Endpoint == nil || *b.Hostname != s.Endpoint.Hostname {
		return false
	}
	port := 0
	if b.Port != nil {
		port = *b.Port
	}
	return s.Endpoint.Port == port && s.Endpoint.Public == (b.Public != nil && *b.Public)
}

func (view *serverStatusView) addDetail(name, address string, extra ...clioutput.Field) {
	fields := []clioutput.Field{{Label: "Service", Value: name}, {Label: "URL", Value: statusValue(address)}, {Label: "Ready", Value: "Unknown"}}
	fields = append(fields, extra...)
	view.details = appendStatusSection(view.details, clioutput.Fields(fields...))
}

func (p statusPublication) matchesService(server, id string, protocol controlv1.ServiceProtocol) bool {
	t := p.tunnel
	return t != nil && server != "" && t.Server == server && id != "" && t.ServiceID == id && t.ServiceProtocol == protocol &&
		(p.service == nil || p.service.RunNumber == t.PublishRunNumber)
}

func (p statusPublication) matchesInventory(origin string, s statusServerService, address string) bool {
	t := p.tunnel
	if !p.matchesService(origin, s.ServiceID, s.Protocol) || s.Endpoint == nil ||
		s.RunNumber != nil && (*s.RunNumber <= 0 || uint64(*s.RunNumber) != t.PublishRunNumber) ||
		s.ServiceRunID != nil && (*s.ServiceRunID == "" || *s.ServiceRunID != t.ServiceRunID) {
		return false
	}
	if s.Endpoint.Public {
		return address != "" && t.PublicURL == address && p.url == address
	}
	// an absent URL alone does not identify a connector-only run.
	return (s.RunNumber != nil || s.ServiceRunID != nil) && t.State == clientstate.TunnelStateReady &&
		t.PublicURL == "" && p.url == "" && serviceendpoint.Valid(string(s.Protocol), s.Endpoint.Hostname, s.Endpoint.Port, false)
}

func (p statusPublication) matchesBinding(project, origin string, b controlv1.AppliedProjectService, protocol controlv1.ServiceProtocol, address string) bool {
	t := p.tunnel
	if p.service == nil || t == nil || project == "" || t.Project != project || p.key != b.Service || t.Service != b.Service ||
		t.Server != origin || protocol == "" || t.ServiceProtocol != protocol {
		return false
	}
	if b.ServiceId != nil {
		return p.matchesService(origin, *b.ServiceId, protocol) && address != "" && t.PublicURL == address && p.url == address
	}
	// a source-verified local declaration describes a named project binding,
	// not a saved server service or run. it supplies neither a URL nor readiness.
	return b.ServiceKind == "local" && b.Public == nil && b.Hostname == nil && b.Port == nil &&
		p.service.PublicURL == t.PublicURL
}

func statusAccess(protocol controlv1.ServiceProtocol, endpoint *controlv1.ServiceEndpoint) (access, reserved string) {
	switch {
	case endpoint == nil:
		return "not reported", ""
	case !endpoint.Public:
		if endpoint.Port > 0 && protocol != controlv1.ServiceProtocolHTTP {
			return "connector-only", strconv.Itoa(endpoint.Port)
		}
		return "connector-only", ""
	default:
		return "public", ""
	}
}
