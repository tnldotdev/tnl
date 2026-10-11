package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type inspectCommand struct {
	List inspectListCommand `cmd:"" help:"List recent local HTTP and database activity for this project."`
	Show inspectShowCommand `cmd:"" help:"Show one locally recorded inspection."`
}

type inspectListCommand struct {
	StateDir     string        `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Output       string        `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	Since        time.Duration `name:"since" default:"24h" help:"Look back this far (up to 24h)."`
	Service      string        `name:"service" help:"Only activity for this project service."`
	Method       string        `name:"method" help:"Only HTTP requests with this method."`
	Status       int           `name:"status" help:"Only HTTP requests with this status."`
	Limit        int           `name:"limit" default:"50" help:"Maximum results (1 to 500)."`
	AllWorktrees bool          `name:"all-worktrees" help:"Include this project in linked Git worktrees."`
}

type inspectShowCommand struct {
	ID       int64  `arg:"" name:"inspection-number" help:"Local number from tnl inspect list."`
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Output   string `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type inspectionRecord struct {
	Number     int64                              `json:"number"`
	Protocol   controlv1.PublicURLServiceProtocol `json:"protocol"`
	TunnelID   string                             `json:"tunnel_id"`
	Project    string                             `json:"project_root"`
	Service    string                             `json:"service,omitempty"`
	ReceivedAt time.Time                          `json:"received_at"`
	DurationMS int64                              `json:"duration_ms"`
	HTTP       *inspectionHTTP                    `json:"http,omitempty"`
	Postgres   *inspectionPostgres                `json:"postgres,omitempty"`
}

type inspectionHTTP struct {
	Method          string          `json:"method"`
	Path            string          `json:"path"`
	Status          int             `json:"status"`
	Origin          string          `json:"origin"`
	CaptureMode     string          `json:"capture_mode"`
	DetailAvailable bool            `json:"detail_available"`
	Detail          json.RawMessage `json:"detail,omitempty"`
}

type inspectionPostgres struct {
	Operation          string `json:"operation"`
	Result             string `json:"result"`
	SQLState           string `json:"sql_state,omitempty"`
	Statement          string `json:"statement,omitempty"`
	StatementTruncated bool   `json:"statement_truncated,omitempty"`
	Rows               int64  `json:"rows,omitempty"`
	CaptureMode        string `json:"capture_mode"`
	DetailAvailable    bool   `json:"detail_available"`
}

const inspectionDetailHint = "set tnl.request_inspection: detailed and restart the tunnel, or pass --request-inspection=detailed on the next run"

func inspectionFromRecord(item clientstate.RequestRecord, includeDetail bool) inspectionRecord {
	record := inspectionRecord{
		Number: item.RequestNumber, Protocol: item.ServiceProtocol, TunnelID: item.TunnelID,
		Project: item.Project, Service: item.Service, ReceivedAt: item.ReceivedAt, DurationMS: item.DurationMS,
	}
	if record.Protocol == controlv1.Postgres {
		record.Postgres = &inspectionPostgres{
			Operation: item.DatabaseOperation, Result: item.DatabaseResult, SQLState: item.SQLState,
			Rows: item.DatabaseRows, CaptureMode: item.CaptureMode, DetailAvailable: item.DetailAvailable,
		}
		if includeDetail && item.DetailAvailable {
			var details struct {
				Statement string `json:"statement"`
				Truncated bool   `json:"truncated"`
			}
			if json.Unmarshal(item.Detail, &details) == nil {
				record.Postgres.Statement = details.Statement
				record.Postgres.StatementTruncated = details.Truncated
			}
		}
		return record
	}
	record.Protocol = controlv1.Http
	record.HTTP = &inspectionHTTP{
		Method: item.Method, Path: item.Path, Status: item.Status, Origin: item.Origin,
		CaptureMode: item.CaptureMode, DetailAvailable: item.DetailAvailable, Detail: item.Detail,
	}
	return record
}

func runInspectList(ctx context.Context, flags inspectListCommand, project string, output io.Writer) error {
	if flags.Since <= 0 || flags.Since > 24*time.Hour || flags.Limit < 1 || flags.Limit > 500 ||
		flags.Status < 0 || flags.Status != 0 && (flags.Status < 100 || flags.Status > 599) {
		return errors.New("since must be at most 24h, limit 1 to 500, and status a valid HTTP status")
	}
	flags.Method = strings.ToUpper(flags.Method)
	if flags.Method != "" && !validInspectionMethod(flags.Method) {
		return errors.New("method must be an HTTP token")
	}
	root, err := clientStateRoot(flags.StateDir)
	if err != nil {
		return err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	_, shared, err := requestRoots(ctx, project)
	if err != nil {
		return err
	}
	items, err := state.ListRequests(ctx, clientstate.RequestFilter{Project: project, SharedProject: shared,
		AllWorktrees: flags.AllWorktrees, Service: flags.Service,
		Method: flags.Method, Status: flags.Status, Since: time.Now().Add(-flags.Since), Limit: flags.Limit})
	if err != nil {
		return err
	}
	records := make([]inspectionRecord, 0, len(items))
	hint := ""
	for _, item := range items {
		records = append(records, inspectionFromRecord(item, false))
		if !item.DetailAvailable {
			hint = inspectionDetailHint
		}
	}
	if flags.Output == "json" {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int                `json:"schema_version"`
			Inspections   []inspectionRecord `json:"inspections"`
			DetailHint    string             `json:"detail_hint,omitempty"`
		}{1, records, hint})
	}
	if len(records) == 0 {
		return writeHumanFrame(output, "tnl inspect list", "no activity", "", clioutput.Text("no matching local activity"))
	}
	blocks := make([]clioutput.Block, 0, len(records))
	for _, record := range records {
		if record.Postgres != nil {
			fields := []clioutput.Field{
				{Label: "protocol", Value: string(record.Protocol)},
				{Label: "result", Value: record.Postgres.Result},
				{Label: "time", Value: record.ReceivedAt.Format(time.RFC3339)},
				{Label: "worktree", Value: record.Project},
			}
			if record.Postgres.SQLState != "" {
				fields = append(fields, clioutput.Field{Label: "SQLSTATE", Value: record.Postgres.SQLState})
			}
			blocks = append(blocks, clioutput.Section(fmt.Sprintf("%d / postgres %s", record.Number, record.Postgres.Operation), clioutput.Fields(fields...)))
			continue
		}
		blocks = append(blocks, clioutput.Section(fmt.Sprintf("%d / %s %s", record.Number, record.HTTP.Method, record.HTTP.Path), clioutput.Fields(
			clioutput.Field{Label: "protocol", Value: string(record.Protocol)},
			clioutput.Field{Label: "status", Value: fmt.Sprint(record.HTTP.Status)},
			clioutput.Field{Label: "from", Value: record.HTTP.Origin},
			clioutput.Field{Label: "time", Value: record.ReceivedAt.Format(time.RFC3339)},
			clioutput.Field{Label: "worktree", Value: record.Project},
		)))
	}
	return writeHumanFrame(output, "tnl inspect list", countState(len(records), "inspection", "inspections"), hint, blocks...)
}

func runInspectShow(ctx context.Context, flags inspectShowCommand, project string, output io.Writer) error {
	if flags.ID <= 0 {
		return errors.New("inspection number must be positive")
	}
	root, err := clientStateRoot(flags.StateDir)
	if err != nil {
		return err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return err
	}
	defer state.Close()
	primary, _, err := requestRoots(ctx, project)
	if err != nil {
		return err
	}
	item, err := state.GetRequest(ctx, primary, flags.ID)
	if err != nil {
		return err
	}
	record := inspectionFromRecord(item, true)
	hint := ""
	if !item.DetailAvailable {
		hint = inspectionDetailHint
	}
	if flags.Output == "json" {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int              `json:"schema_version"`
			Inspection    inspectionRecord `json:"inspection"`
			DetailHint    string           `json:"detail_hint,omitempty"`
		}{1, record, hint})
	}
	fields := []clioutput.Field{
		{Label: "time", Value: record.ReceivedAt.Format(time.RFC3339Nano)},
		{Label: "protocol", Value: string(record.Protocol)},
		{Label: "duration", Value: fmt.Sprintf("%d ms", record.DurationMS)},
		{Label: "service", Value: record.Service},
		{Label: "worktree", Value: record.Project},
		{Label: "tunnel", Value: record.TunnelID},
	}
	if record.Postgres != nil {
		fields = append(fields,
			clioutput.Field{Label: "operation", Value: record.Postgres.Operation},
			clioutput.Field{Label: "result", Value: record.Postgres.Result},
			clioutput.Field{Label: "rows", Value: fmt.Sprint(record.Postgres.Rows)},
		)
		if record.Postgres.SQLState != "" {
			fields = append(fields, clioutput.Field{Label: "SQLSTATE", Value: record.Postgres.SQLState})
		}
	} else {
		fields = append(fields,
			clioutput.Field{Label: "method", Value: record.HTTP.Method},
			clioutput.Field{Label: "path", Value: record.HTTP.Path},
			clioutput.Field{Label: "status", Value: fmt.Sprint(record.HTTP.Status)},
			clioutput.Field{Label: "from", Value: record.HTTP.Origin},
		)
	}
	blocks := []clioutput.Block{clioutput.Fields(fields...)}
	if record.Postgres != nil && record.Postgres.DetailAvailable {
		blocks = append(blocks, clioutput.Text("the captured statement is available with --output json"))
	} else if record.HTTP != nil && record.HTTP.DetailAvailable {
		blocks = append(blocks, clioutput.Text("detailed query, headers, and bodies are available with --output json"))
	} else {
		blocks = append(blocks, clioutput.Text("summary only; "+inspectionDetailHint))
	}
	return writeHumanFrame(output, "tnl inspect show", fmt.Sprintf("inspection %d", record.Number), "", blocks...)
}

func validInspectionMethod(method string) bool {
	if method == "" || len(method) > 32 {
		return false
	}
	for _, c := range method {
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}
