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
	Since        time.Duration `name:"since" help:"Only activity within this time; defaults to all retained inspections."`
	Service      string        `name:"service" help:"Only activity for this project service."`
	Protocol     string        `name:"protocol" help:"Only HTTP or TCP activity: http, postgres, mysql, or redis."`
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
	Number     int64                              `json:"number"`
	Protocol   controlv1.PublicURLServiceProtocol `json:"protocol"`
	TunnelID   string                             `json:"tunnel_id"`
	Project    string                             `json:"project_root"`
	Service    string                             `json:"service,omitempty"`
	ReceivedAt time.Time                          `json:"received_at"`
	DurationMS int64                              `json:"duration_ms"`
	Result     inspection.Result                  `json:"result"`
	HTTP       *inspectionHTTP                    `json:"http,omitempty"`
	Postgres   *inspectionSQL                     `json:"postgres,omitempty"`
	MySQL      *inspectionMySQL                   `json:"mysql,omitempty"`
	Redis      *inspectionRedis                   `json:"redis,omitempty"`
}

type inspectionHTTP struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Origin string `json:"origin"`
}

type inspectionSQL struct {
	Operation inspection.Operation `json:"operation"`
	SQLState  string               `json:"sql_state,omitempty"`
	Rows      int64                `json:"rows"`
}

type inspectionMySQL struct {
	inspectionSQL
	ErrorCode  int64 `json:"error_code,omitempty"`
	ResultSets int64 `json:"result_sets"`
}

type inspectionRedis struct {
	Command string `json:"command"`
}

func inspectionFromRecord(item clientstate.InspectionRecord) (inspectionRecord, error) {
	record := inspectionRecord{
		Number: item.Number, Protocol: item.Protocol, TunnelID: item.TunnelID,
		Project: item.Project, Service: item.Service, ReceivedAt: item.ReceivedAt, DurationMS: item.DurationMS,
		Result: item.Result,
	}
	switch item.Protocol {
	case controlv1.Http:
		record.Result = inspection.HTTPResult(item.Status)
		record.HTTP = &inspectionHTTP{
			Method: item.Method, Path: item.Path, Status: item.Status, Origin: item.Origin,
		}
	case controlv1.Postgres, controlv1.Mysql:
		if !item.Operation.Valid() || !item.Result.Valid() {
			return record, errors.New("inspection has an invalid database outcome")
		}
		sql := inspectionSQL{Operation: item.Operation, SQLState: item.SQLState, Rows: item.Rows}
		if item.Protocol == controlv1.Postgres {
			record.Postgres = &sql
		} else {
			record.MySQL = &inspectionMySQL{inspectionSQL: sql, ErrorCode: item.MySQLErrorCode, ResultSets: item.ResultSets}
		}
	case controlv1.Redis:
		if item.RedisCommand == "" || !item.Result.Valid() {
			return record, errors.New("inspection has an invalid Redis outcome")
		}
		record.Redis = &inspectionRedis{Command: item.RedisCommand}
	default:
		return record, fmt.Errorf("inspection has an unknown protocol %q", item.Protocol)
	}
	return record, nil
}

func runInspectList(ctx context.Context, flags inspectListCommand, project string, output io.Writer) error {
	if flags.Since < 0 || flags.Since > inspection.MaxRetention || flags.Limit < 1 || flags.Limit > 500 ||
		flags.Status < 0 || flags.Status != 0 && (flags.Status < 100 || flags.Status > 599) {
		return errors.New("since must be at most 720h, limit 1 to 500, and status a valid HTTP status")
	}
	flags.Method = strings.ToUpper(flags.Method)
	protocol := controlv1.PublicURLServiceProtocol(flags.Protocol)
	if flags.Protocol != "" && protocol != controlv1.Http && protocol != controlv1.Postgres && protocol != controlv1.Mysql && protocol != controlv1.Redis {
		return errors.New("protocol must be http, postgres, mysql, or redis")
	}
	if protocol != "" && protocol != controlv1.Http && (flags.Method != "" || flags.Status != 0) {
		return errors.New("method and status only filter HTTP inspections")
	}
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
	_, shared, err := inspectionRoots(ctx, project)
	if err != nil {
		return err
	}
	var since time.Time
	if flags.Since > 0 {
		since = time.Now().Add(-flags.Since)
	}
	items, err := state.ListInspections(ctx, clientstate.InspectionFilter{Project: project, SharedProject: shared,
		AllWorktrees: flags.AllWorktrees, Service: flags.Service, Protocol: protocol,
		Method: flags.Method, Status: flags.Status, Result: inspection.Result(flags.Result),
		Since: since, Limit: flags.Limit})
	if err != nil {
		return err
	}
	records := make([]inspectionRecord, 0, len(items))
	for _, item := range items {
		record, err := inspectionFromRecord(item)
		if err != nil {
			return err
		}
		records = append(records, record)
	}
	if flags.Output == "json" {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int                `json:"schema_version"`
			Inspections   []inspectionRecord `json:"inspections"`
		}{2, records})
	}
	if len(records) == 0 {
		return writeHumanFrame(output, "tnl inspect list", "no activity", "", clioutput.Text("no matching local activity"))
	}
	blocks := make([]clioutput.Block, 0, len(records))
	for _, record := range records {
		if record.Postgres != nil || record.MySQL != nil {
			var sql inspectionSQL
			if record.Postgres != nil {
				sql = *record.Postgres
			} else {
				sql = record.MySQL.inspectionSQL
			}
			fields := []clioutput.Field{
				{Label: "service", Value: record.Service}, {Label: "result", Value: string(record.Result)},
				{Label: "time", Value: record.ReceivedAt.Format(time.RFC3339)},
			}
			if sql.SQLState != "" {
				fields = append(fields, clioutput.Field{Label: "SQLSTATE", Value: sql.SQLState})
			}
			blocks = append(blocks, clioutput.Section(fmt.Sprintf("%d / %s %s", record.Number, record.Protocol, sql.Operation), clioutput.Fields(fields...)))
			continue
		}
		if record.Redis != nil {
			blocks = append(blocks, clioutput.Section(fmt.Sprintf("%d / redis %s", record.Number, record.Redis.Command), clioutput.Fields(
				clioutput.Field{Label: "service", Value: record.Service}, clioutput.Field{Label: "result", Value: string(record.Result)},
				clioutput.Field{Label: "time", Value: record.ReceivedAt.Format(time.RFC3339)},
			)))
			continue
		}
		blocks = append(blocks, clioutput.Section(fmt.Sprintf("%d / %s %s", record.Number, record.HTTP.Method, record.HTTP.Path), clioutput.Fields(
			clioutput.Field{Label: "protocol", Value: string(record.Protocol)},
			clioutput.Field{Label: "service", Value: record.Service},
			clioutput.Field{Label: "result", Value: string(record.Result)},
			clioutput.Field{Label: "status", Value: fmt.Sprint(record.HTTP.Status)},
			clioutput.Field{Label: "from", Value: record.HTTP.Origin},
			clioutput.Field{Label: "time", Value: record.ReceivedAt.Format(time.RFC3339)},
			clioutput.Field{Label: "worktree", Value: record.Project},
		)))
	}
	return writeHumanFrame(output, "tnl inspect list", countState(len(records), "inspection", "inspections"), "", blocks...)
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
	primary, _, err := inspectionRoots(ctx, project)
	if err != nil {
		return err
	}
	item, err := state.GetInspection(ctx, primary, flags.ID)
	if err != nil {
		return err
	}
	record, err := inspectionFromRecord(item)
	if err != nil {
		return err
	}
	if flags.Output == "json" {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int              `json:"schema_version"`
			Inspection    inspectionRecord `json:"inspection"`
		}{2, record})
	}
	fields := []clioutput.Field{
		clioutput.Field{Label: "time", Value: record.ReceivedAt.Format(time.RFC3339Nano)},
		clioutput.Field{Label: "protocol", Value: string(record.Protocol)},
		clioutput.Field{Label: "result", Value: string(record.Result)},
		clioutput.Field{Label: "duration", Value: fmt.Sprintf("%d ms", record.DurationMS)},
		clioutput.Field{Label: "service", Value: record.Service},
		clioutput.Field{Label: "worktree", Value: record.Project},
		clioutput.Field{Label: "tunnel", Value: record.TunnelID},
	}
	if record.HTTP != nil {
		fields = append(fields, clioutput.Field{Label: "method", Value: record.HTTP.Method},
			clioutput.Field{Label: "path", Value: record.HTTP.Path}, clioutput.Field{Label: "status", Value: fmt.Sprint(record.HTTP.Status)},
			clioutput.Field{Label: "from", Value: record.HTTP.Origin})
	} else if record.Redis != nil {
		fields = append(fields, clioutput.Field{Label: "command", Value: record.Redis.Command})
	} else {
		var sql inspectionSQL
		if record.Postgres != nil {
			sql = *record.Postgres
		} else {
			sql = record.MySQL.inspectionSQL
		}
		fields = append(fields, clioutput.Field{Label: "operation", Value: string(sql.Operation)}, clioutput.Field{Label: "rows", Value: fmt.Sprint(sql.Rows)})
		if sql.SQLState != "" {
			fields = append(fields, clioutput.Field{Label: "SQLSTATE", Value: sql.SQLState})
		}
		if record.MySQL != nil {
			fields = append(fields, clioutput.Field{Label: "result sets", Value: fmt.Sprint(record.MySQL.ResultSets)})
			if record.MySQL.ErrorCode != 0 {
				fields = append(fields, clioutput.Field{Label: "error code", Value: fmt.Sprint(record.MySQL.ErrorCode)})
			}
		}
	}
	return writeHumanFrame(output, "tnl inspect show", fmt.Sprintf("inspection %d", record.Number), "", clioutput.Fields(fields...))
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
