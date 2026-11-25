package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type auditCommand struct {
	List auditListCommand
}

type auditListCommand struct {
	scopedTeamFlags `embed:""`
	Service         string           `name:"service" help:"Service name, immutable service ID, hostname, host:port, or service URL."`
	Selector        string           `arg:"" name:"service-or-address" optional:"" help:"Service name, immutable service ID, hostname, host:port, or service URL."`
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
		_, err := auditCursor(flags.After)
		if err != nil {
			return failure.Wrap("select audit cursor", failure.InvalidTunnelFlags, err)
		}
		params.After = &flags.After
	}
	if flags.Selector != "" {
		if flags.Service != "" {
			return serviceInputError(failure.InvalidTunnelFlags, "Pass a service selector either as an argument or with --service, not both.")
		}
		flags.Service = flags.Selector
	}
	input, err := parseWholeService(flags.Service, failure.InvalidTunnelFlags)
	if err != nil {
		return err
	}
	switch input.Kind {
	case naming.SelectorID:
		params.ServiceId = &input.ID
	case naming.SelectorName:
		params.Service = &input.Name
	case naming.SelectorAddress:
		if input.Scheme == "" && !input.ExplicitPort {
			params.Service = &input.Host
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
	if input.Kind == naming.SelectorAddress && params.Service == nil {
		item, err := lookupManagedService(ctx, session, input)
		if err != nil {
			return err
		}
		params.ServiceId = &item.Id
		flags.Service = item.Id
	}
	page, err := readServiceAudit(ctx, session.Authenticated().Control, current.Team().Id, params, flags.Limit)
	if err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return failure.Wrap("write service audit", failure.OutputUnavailable, json.NewEncoder(output).Encode(page))
	}
	return renderServiceAudit(output, page, flags, since, flags.followupScope(ctx, session, current.Team().Id))
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
		previous, _ = auditCursor(*params.After)
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
			if err != nil || cursor <= previous || event.TeamId != team || event.Id == "" || !opaqueid.Valid(event.ServiceId, opaqueid.ServicePrefix) || event.EventType == "" || event.OccurredAt.IsZero() || !event.ServiceKind.Valid() {
				return invalid()
			}
			previous = cursor
		}
		result.Events = append(result.Events, page.Events...)
		if page.NextCursor == nil {
			return result, nil
		}
		next, err := auditCursor(*page.NextCursor)
		if err != nil || len(page.Events) == 0 || next != previous {
			return invalid()
		}
		result.NextCursor = page.NextCursor
		if len(result.Events) == limit {
			return result, nil
		}
		params.After = page.NextCursor
		result.NextCursor = nil
	}
	return result, nil
}

func renderServiceAudit(output io.Writer, page controlv1.ServiceAuditPage, flags auditListCommand, since time.Time, scope commandScope) error {
	var rows [][]string
	for _, event := range page.Events {
		var detail []string
		for _, value := range []*string{event.Outcome, event.Reason} {
			if value != nil {
				detail = append(detail, *value)
			}
		}
		rows = append(rows, []string{event.OccurredAt.UTC().Format(time.RFC3339), event.EventType, event.ServiceId, strings.Join(detail, ": ")})
	}
	blocks := []clioutput.Block{clioutput.Table([]string{"TIME", "EVENT", "SERVICE", "OUTCOME"}, rows, "No matching audit events.")}
	if page.NextCursor != nil {
		args := []string{"--since=" + since.Format(time.RFC3339Nano)}
		if flags.Service != "" {
			args = append(args, "--service="+flags.Service)
		}
		if flags.Limit != 100 {
			args = append(args, "--limit="+strconv.Itoa(flags.Limit))
		}
		blocks = append(blocks, scope.nextPage("audit list", *page.NextCursor, args...))
	}
	return writeResult(output, blocks...)
}

func (a *commandApp) newAuditCommand() *cobra.Command {
	f := a.flags
	cAudit := &cobra.Command{Use: "audit", Short: "Read audit events for your team's services.", GroupID: "observe"}
	cAuditList := &cobra.Command{Use: "list", Short: "Read service audit events with team-manager access."}
	a.leaf(cAuditList, &f.Audit.List, func(call commandCall) error {
		return runAuditList(call.ctx, f.Audit.List, a.out, a.errOut)
	})
	bind := cAuditList.Args
	cAuditList.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) == 1 && args[0] == "" || cmd.Flags().Changed("service") && f.Audit.List.Service == "" {
			return serviceInputError(failure.InvalidTunnelFlags, "The service selector cannot be empty.")
		}
		return bind(cmd, args)
	}
	cAudit.AddCommand(cAuditList)
	a.useDefault(cAudit, cAuditList)
	return cAudit
}
