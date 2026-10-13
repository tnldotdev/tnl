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
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type inspectCommand struct {
	List inspectListCommand `cmd:"" help:"List recent local HTTP and supported TCP activity for this project."`
	Show inspectShowCommand `cmd:"" help:"Show one locally recorded inspection."`
}

type inspectListCommand struct {
	StateDir     string        `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Output       string        `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	Since        time.Duration `name:"since" default:"24h" help:"Look back this far (up to 24h)."`
	Service      string        `name:"service" help:"Only activity for this project service."`
	Result       string        `name:"result" help:"Only successful or failed activity: ok or error."`
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
	Number          int64                              `json:"number"`
	Protocol        controlv1.PublicURLServiceProtocol `json:"protocol"`
	TunnelID        string                             `json:"tunnel_id"`
	Project         string                             `json:"project_root"`
	Service         string                             `json:"service,omitempty"`
	ReceivedAt      time.Time                          `json:"received_at"`
	DurationMS      int64                              `json:"duration_ms"`
	Result          inspection.Result                  `json:"result"`
	CaptureMode     string                             `json:"capture_mode"`
	DetailAvailable bool                               `json:"detail_available"`
	HTTP            *inspectionHTTP                    `json:"http,omitempty"`
}

type inspectionHTTP struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Status int             `json:"status"`
	Origin string          `json:"origin"`
	Detail json.RawMessage `json:"detail,omitempty"`
}

const inspectionDetailHint = "use --request-inspection=detailed on the next run"

func httpInspection(item clientstate.RequestRecord) inspectionRecord {
	return inspectionRecord{
		Number: item.RequestNumber, Protocol: controlv1.Http, TunnelID: item.TunnelID,
		Project: item.Project, Service: item.Service, ReceivedAt: item.ReceivedAt, DurationMS: item.DurationMS,
		Result: inspection.HTTPResult(item.Status), CaptureMode: item.CaptureMode, DetailAvailable: item.DetailAvailable,
		HTTP: &inspectionHTTP{
			Method: item.Method, Path: item.Path, Status: item.Status, Origin: item.Origin,
			Detail: item.Detail,
		},
	}
}

func runInspectList(ctx context.Context, flags inspectListCommand, project string, output io.Writer) error {
	if flags.Since <= 0 || flags.Since > 24*time.Hour || flags.Limit < 1 || flags.Limit > 500 ||
		flags.Status < 0 || flags.Status != 0 && (flags.Status < 100 || flags.Status > 599) {
		return errors.New("since must be at most 24h, limit 1 to 500, and status a valid HTTP status")
	}
	flags.Method = strings.ToUpper(flags.Method)
	if flags.Result != "" && !inspection.Result(flags.Result).Valid() {
		return errors.New("result must be ok or error")
	}
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
		Method: flags.Method, Status: flags.Status, Result: inspection.Result(flags.Result),
		Since: time.Now().Add(-flags.Since), Limit: flags.Limit})
	if err != nil {
		return err
	}
	records := make([]inspectionRecord, 0, len(items))
	hint := ""
	for _, item := range items {
		records = append(records, httpInspection(item))
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
		blocks = append(blocks, clioutput.Section(fmt.Sprintf("%d / %s %s", record.Number, record.HTTP.Method, record.HTTP.Path), clioutput.Fields(
			clioutput.Field{Label: "protocol", Value: string(record.Protocol)},
			clioutput.Field{Label: "result", Value: string(record.Result)},
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
	record := httpInspection(item)
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
	blocks := []clioutput.Block{clioutput.Fields(
		clioutput.Field{Label: "time", Value: record.ReceivedAt.Format(time.RFC3339Nano)},
		clioutput.Field{Label: "protocol", Value: string(record.Protocol)},
		clioutput.Field{Label: "result", Value: string(record.Result)},
		clioutput.Field{Label: "method", Value: record.HTTP.Method},
		clioutput.Field{Label: "path", Value: record.HTTP.Path},
		clioutput.Field{Label: "status", Value: fmt.Sprint(record.HTTP.Status)},
		clioutput.Field{Label: "duration", Value: fmt.Sprintf("%d ms", record.DurationMS)},
		clioutput.Field{Label: "from", Value: record.HTTP.Origin},
		clioutput.Field{Label: "service", Value: record.Service},
		clioutput.Field{Label: "worktree", Value: record.Project},
		clioutput.Field{Label: "tunnel", Value: record.TunnelID},
	)}
	if record.DetailAvailable {
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
