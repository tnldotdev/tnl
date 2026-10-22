package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type auditCommand struct {
	List auditListCommand `cmd:"" help:"Read service audit events with team-manager access."`
}

type auditListCommand struct {
	scopedTeamFlags `embed:""`
	Service         string           `name:"service" help:"Private service name, public hostname, or immutable service ID."`
	Since           string           `name:"since" default:"24h" help:"Read events since a positive duration such as 24h, or an RFC3339 timestamp."`
	After           string           `name:"after" help:"Resume after the cursor returned by a previous audit list."`
	Limit           int              `name:"limit" default:"100" help:"Maximum events to return, from 1 to 10000."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type serviceAuditReader interface {
	ListServiceAudit(context.Context, string, controlv1.ListServiceAuditParams) (controlv1.ServiceAuditPage, error)
}

func auditSince(value string, now time.Time) (time.Time, error) {
	if value == "" {
		value = "24h"
	}
	if period, err := time.ParseDuration(value); err == nil && period > 0 {
		return now.UTC().Add(-period), nil
	}
	if since, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return since.UTC(), nil
	}
	return time.Time{}, failure.Wrap("select audit time", failure.InvalidTunnelFlags, errors.New("--since requires a positive duration or an RFC3339 timestamp"))
}

func auditCursor(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 || strconv.FormatInt(parsed, 10) != value {
		return 0, errors.New("audit cursor must be a canonical nonnegative integer")
	}
	return parsed, nil
}

func runAuditList(ctx context.Context, flags auditListCommand, output, diagnostics io.Writer) error {
	since, err := auditSince(flags.Since, time.Now())
	if err != nil {
		return err
	}
	if flags.Limit < 1 || flags.Limit > 10000 {
		return failure.Wrap("select audit limit", failure.InvalidTunnelFlags, errors.New("--limit must be from 1 to 10000"))
	}
	params := controlv1.ListServiceAuditParams{Since: &since}
	if flags.After != "" {
		after, err := auditCursor(flags.After)
		if err != nil {
			return failure.Wrap("select audit cursor", failure.InvalidTunnelFlags, err)
		}
		params.After = &after
	}
	if flags.Service != "" {
		if len(flags.Service) > 253 || strings.TrimSpace(flags.Service) != flags.Service || strings.ContainsAny(flags.Service, "\x00\r\n") {
			return failure.Wrap("select audit service", failure.InvalidTunnelFlags, errors.New("--service requires a service name, hostname or ID"))
		}
		if opaqueid.Valid(flags.Service, opaqueid.PrivateServicePrefix) || opaqueid.Valid(flags.Service, opaqueid.PublicURLPrefix) {
			params.ServiceId = &flags.Service
		} else {
			params.Service = &flags.Service
		}
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl audit list", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	page, err := readServiceAudit(ctx, session.Authenticated().Control, current.Team().Id, params, flags.Limit)
	if err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write service audit", failure.OutputUnavailable, json.NewEncoder(output).Encode(page))
	}
	return renderServiceAudit(output, page)
}

// readServiceAudit bounds the finite result and rejects stalled, cycling or
// backward cursors before issuing another request. filters never change pages.
func readServiceAudit(ctx context.Context, reader serviceAuditReader, team string, params controlv1.ListServiceAuditParams, limit int) (controlv1.ServiceAuditPage, error) {
	result := controlv1.ServiceAuditPage{Events: []controlv1.ServiceAuditEvent{}}
	if limit < 1 || limit > 10000 {
		return result, failure.Wrap("select audit limit", failure.InvalidTunnelFlags, errors.New("audit event limit is outside its bounds"))
	}
	previous := int64(0)
	if params.After != nil {
		previous = *params.After
	}
	invalid := func() (controlv1.ServiceAuditPage, error) {
		return controlv1.ServiceAuditPage{}, failure.Wrap("read service audit", failure.ServerResponseInvalid, errors.New("control returned a nonadvancing or invalid service audit page"))
	}
	for len(result.Events) < limit {
		pageLimit := min(256, limit-len(result.Events))
		params.Limit = &pageLimit
		page, err := reader.ListServiceAudit(ctx, team, params)
		if err != nil {
			return controlv1.ServiceAuditPage{}, err
		}
		if len(page.Events) > pageLimit {
			return invalid()
		}
		for _, event := range page.Events {
			cursor, err := auditCursor(event.Cursor)
			if err != nil || cursor <= previous || event.TeamId != team || event.Id == "" || event.ServiceId == "" || event.EventType == "" || event.OccurredAt.IsZero() || !event.ServiceKind.Valid() {
				return invalid()
			}
			previous = cursor
		}
		result.Events = append(result.Events, page.Events...)
		if page.NextCursor == nil {
			return result, nil
		}
		next, err := auditCursor(*page.NextCursor)
		if err != nil || len(page.Events) == 0 || next != previous || params.After != nil && next <= *params.After {
			return invalid()
		}
		result.NextCursor = page.NextCursor
		if len(result.Events) == limit {
			return result, nil
		}
		params.After = &next
		result.NextCursor = nil
	}
	return result, nil
}

func renderServiceAudit(output io.Writer, page controlv1.ServiceAuditPage) error {
	blocks := make([]clioutput.Block, 0, len(page.Events))
	for _, event := range page.Events {
		fields := []clioutput.Field{
			{Label: "occurred at", Value: event.OccurredAt.UTC().Format(time.RFC3339Nano)},
			{Label: "service ID", Value: event.ServiceId}, {Label: "kind", Value: string(event.ServiceKind)},
			{Label: "event ID", Value: event.Id}, {Label: "cursor", Value: event.Cursor},
		}
		for _, optional := range []struct {
			label string
			value *string
		}{
			{"outcome", event.Outcome}, {"reason", event.Reason}, {"actor identity ID", event.ActorIdentityId},
			{"publisher ID", event.PublisherIdentityId}, {"device ID", event.DeviceId}, {"run ID", event.RunId},
			{"visitor connection ID", event.VisitorConnectionId}, {"source IP", event.SourceIp},
		} {
			if optional.value != nil {
				fields = append(fields, clioutput.Field{Label: optional.label, Value: *optional.value})
			}
		}
		if event.ConfigurationRevision != nil {
			fields = append(fields, clioutput.Field{Label: "configuration revision", Value: strconv.FormatInt(*event.ConfigurationRevision, 10)})
		}
		blocks = append(blocks, clioutput.Section(event.EventType, clioutput.Fields(fields...)))
	}
	if len(blocks) == 0 {
		blocks = append(blocks, clioutput.Text("no service audit events match the filters"))
	}
	footer := ""
	if page.NextCursor != nil {
		footer = "continue with --after " + *page.NextCursor
	}
	return writeHumanFrame(output, "tnl audit list", countState(len(page.Events), "event", "events"), footer, blocks...)
}
