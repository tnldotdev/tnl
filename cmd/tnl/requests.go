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
)

type requestsCommand struct {
	List requestsListCommand `cmd:"" help:"List recent local HTTP requests for this project."`
	Show requestsShowCommand `cmd:"" help:"Show one locally recorded HTTP request."`
}

type requestsListCommand struct {
	StateDir string        `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Output   string        `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
	Since    time.Duration `name:"since" default:"24h" help:"Look back this far (up to 24h)."`
	Service  string        `name:"service" help:"Only requests for this project service."`
	Method   string        `name:"method" help:"Only requests with this HTTP method."`
	Status   int           `name:"status" help:"Only requests with this HTTP status."`
	Limit    int           `name:"limit" default:"50" help:"Maximum results (1 to 500)."`
}

type requestsShowCommand struct {
	ID       int64  `arg:"" name:"request-id" help:"Local request ID from tnl requests list."`
	StateDir string `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Output   string `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

func runRequestsList(ctx context.Context, flags requestsListCommand, project string, output io.Writer) error {
	if flags.Since <= 0 || flags.Since > 24*time.Hour || flags.Limit < 1 || flags.Limit > 500 ||
		flags.Status < 0 || flags.Status != 0 && (flags.Status < 100 || flags.Status > 599) {
		return errors.New("since must be at most 24h, limit 1 to 500, and status a valid HTTP status")
	}
	flags.Method = strings.ToUpper(flags.Method)
	if flags.Method != "" && !validRequestMethod(flags.Method) {
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
	items, err := state.ListRequests(ctx, clientstate.RequestFilter{Project: project, Service: flags.Service,
		Method: flags.Method, Status: flags.Status, Since: time.Now().Add(-flags.Since), Limit: flags.Limit})
	if err != nil {
		return err
	}
	if flags.Output == "json" {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int                         `json:"schema_version"`
			Requests      []clientstate.RequestRecord `json:"requests"`
		}{1, items})
	}
	if len(items) == 0 {
		return writeHumanFrame(output, "tnl requests list", "no requests", "", clioutput.Text("no matching local requests"))
	}
	blocks := make([]clioutput.Block, 0, len(items))
	for _, item := range items {
		blocks = append(blocks, clioutput.Section(fmt.Sprintf("%d / %s %s", item.ID, item.Method, item.Path), clioutput.Fields(
			clioutput.Field{Label: "status", Value: fmt.Sprint(item.Status)},
			clioutput.Field{Label: "from", Value: item.Origin},
			clioutput.Field{Label: "time", Value: item.ReceivedAt.Format(time.RFC3339)},
		)))
	}
	return writeHumanFrame(output, "tnl requests list", countState(len(items), "request", "requests"), "", blocks...)
}

func runRequestsShow(ctx context.Context, flags requestsShowCommand, project string, output io.Writer) error {
	if flags.ID <= 0 {
		return errors.New("request ID must be positive")
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
	item, err := state.GetRequest(ctx, project, flags.ID)
	if err != nil {
		return err
	}
	if flags.Output == "json" {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int                       `json:"schema_version"`
			Request       clientstate.RequestRecord `json:"request"`
		}{1, item})
	}
	return writeHumanFrame(output, "tnl requests show", fmt.Sprintf("request %d", item.ID), "",
		clioutput.Fields(
			clioutput.Field{Label: "time", Value: item.ReceivedAt.Format(time.RFC3339Nano)},
			clioutput.Field{Label: "method", Value: item.Method},
			clioutput.Field{Label: "path", Value: item.Path},
			clioutput.Field{Label: "status", Value: fmt.Sprint(item.Status)},
			clioutput.Field{Label: "duration", Value: fmt.Sprintf("%d ms", item.DurationMS)},
			clioutput.Field{Label: "from", Value: item.Origin},
			clioutput.Field{Label: "service", Value: item.Service},
			clioutput.Field{Label: "tunnel", Value: item.TunnelID},
		))
}

func validRequestMethod(method string) bool {
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
