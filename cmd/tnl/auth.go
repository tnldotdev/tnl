package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"golang.org/x/term"
)

type authCommand struct {
	Status  authStatusCommand  `cmd:"" help:"Show local credentials; --check silently validates with the server."`
	Login   authLoginCommand   `cmd:"" help:"Log in explicitly, or manage a resumable login operation."`
	Logout  logoutCommand      `cmd:"" help:"Cancel login operations and remove the saved control session."`
	Browser authBrowserCommand `cmd:"" help:"Sign in to visit an HTTP public URL in a browser."`
}

type authStatusCommand struct {
	remoteFlags `embed:""`
	Check       bool             `help:"Refresh if needed and validate credentials with the server."`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type loginCommand struct {
	Team      string           `name:"team" help:"Team name to authenticate for; defaults to the project or saved team."`
	ServerURL string           `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the project or selected server."`
	StateDir  string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Open      bool             `name:"open" help:"Open the approval URL in a browser."`
	Timeout   time.Duration    `name:"timeout" default:"10m" help:"Maximum wait; a device login operation can be resumed after timeout."`
	Output    statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type authLoginCommand struct {
	loginCommand `embed:""`
	Run          struct{}             `cmd:"" default:"1" hidden:""`
	Start        struct{}             `cmd:"" help:"Return a pending device login operation immediately."`
	Wait         authOperationCommand `cmd:"" help:"Wait for approval and save credentials for this operation."`
	Inspect      authOperationCommand `cmd:"" help:"Show the current state of a saved login attempt."`
	Cancel       authOperationCommand `cmd:"" help:"Cancel this login attempt so it cannot save a session."`
}

type authOperationCommand struct {
	ID string `arg:"" name:"operation-id" help:"Operation ID returned by auth login start."`
}

type logoutCommand struct {
	ServerURL string           `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the project or selected server."`
	StateDir  string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Output    statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

func authLoginConfig(flags loginCommand, server string, state *clientstate.Database, input io.Reader, diagnostics io.Writer) (clientauth.Config, error) {
	config := clientauth.Config{ServerEndpoint: server, State: state, Diagnostics: diagnostics,
		Team:                 flags.Team,
		LoginTimeout:         flags.Timeout,
		AuthenticationPrompt: authenticationPrompt(diagnostics, "tnl auth login")}
	config.ObserveLogin = func(op clientstate.AuthOperation) error {
		return writeAuthOperation(diagnostics, "tnl auth login", op, flags.Output)
	}
	if flags.Open && flags.Output != statusOutputJSON {
		config.OpenURL = interactiveBrowserOpener(input)
	}
	return config, nil
}

func runLogin(ctx context.Context, flags loginCommand, input io.Reader, output, errorOutput io.Writer) error {
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	config, err := authLoginConfig(flags, serverURL, state, input, errorOutput)
	if err != nil {
		return err
	}
	_, err = clientauth.Login(ctx, config)
	if err != nil {
		return err
	}
	return writeLoginResult(ctx, config, output, flags.Output)
}

func writeLoginResult(ctx context.Context, config clientauth.Config, output io.Writer, mode statusOutputMode) error {
	status, err := clientauth.Status(ctx, config, false)
	if err != nil {
		return err
	}
	if status.Status == "available" && status.Source == "saved_session" {
		status.Status = "authenticated"
	}
	return writeAuthStatus(output, "tnl auth login", status, mode)
}

func runAuthLoginStart(ctx context.Context, flags loginCommand, input io.Reader, output, diagnostics io.Writer) error {
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	config, err := authLoginConfig(flags, server, state, input, diagnostics)
	if err != nil {
		return err
	}
	op, err := clientauth.StartLogin(ctx, config)
	if err != nil {
		return err
	}
	return writeAuthOperation(output, "tnl auth login start", op, flags.Output)
}

func runAuthLoginOperation(ctx context.Context, flags loginCommand, id, action string, output, diagnostics io.Writer) error {
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	config := clientauth.Config{ServerEndpoint: server, State: state, Diagnostics: diagnostics}
	var op clientstate.AuthOperation
	switch action {
	case "wait":
		if flags.Output != statusOutputJSON {
			pending, inspectErr := clientauth.InspectLogin(ctx, config, id)
			if inspectErr != nil {
				return inspectErr
			}
			if pending.Phase == clientstate.AuthPending {
				if err := writeAuthOperation(diagnostics, "tnl auth login wait", pending, statusOutputHuman); err != nil {
					return err
				}
				if flags.Open {
					if open := interactiveBrowserOpener(os.Stdin); open != nil {
						_ = open(pending.ApprovalURL)
					}
				}
			}
		}
		op, err = clientauth.WaitLogin(ctx, config, id, flags.Timeout)
	case "inspect":
		op, err = clientauth.InspectLogin(ctx, config, id)
	case "cancel":
		op, err = clientauth.CancelLogin(ctx, config, id)
	}
	if err != nil {
		return err
	}
	return writeAuthOperation(output, "tnl auth login "+action, op, flags.Output)
}

func runAuthStatus(ctx context.Context, flags authStatusCommand, output, diagnostics io.Writer) error {
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	status, err := clientauth.Status(ctx, clientauth.Config{ServerEndpoint: server, State: state, AccessToken: flags.AccessToken, Diagnostics: diagnostics}, flags.Check)
	if err != nil {
		return err
	}
	return writeAuthStatus(output, "tnl auth status", status, flags.Output)
}

func writeAuthStatus(output io.Writer, command string, status clientauth.StatusResult, mode statusOutputMode) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(status)
	}
	fields := []clioutput.Field{{Label: "control", Value: status.Server}, {Label: "source", Value: status.Source}, {Label: "checked", Value: strconv.FormatBool(status.Checked)}}
	if status.AccessExpiresAt != nil {
		fields = append(fields, clioutput.Field{Label: "access expires", Value: status.AccessExpiresAt.UTC().Format(time.RFC3339)})
	}
	if status.RefreshExpiresAt != nil {
		fields = append(fields, clioutput.Field{Label: "refresh expires", Value: status.RefreshExpiresAt.UTC().Format(time.RFC3339)})
	}
	return writeHumanFrame(output, command, strings.ReplaceAll(status.Status, "_", " "), "", clioutput.Fields(fields...))
}

func writeAuthOperation(output io.Writer, command string, op clientstate.AuthOperation, mode statusOutputMode) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int `json:"schema_version"`
			clientstate.AuthOperation
		}{1, op})
	}
	fields := []clioutput.Field{{Label: "operation", Value: op.ID}, {Label: "control", Value: op.Server}, {Label: "method", Value: op.Method}}
	if op.Phase == clientstate.AuthPending {
		fields = append(fields, clioutput.Field{Label: "approve", Value: op.ApprovalURL}, clioutput.Field{Label: "code", Value: op.UserCode},
			clioutput.Field{Label: "expires", Value: op.ExpiresAt.UTC().Format(time.RFC3339)}, clioutput.Field{Label: "interval", Value: op.Interval.String()})
	}
	footer := ""
	if op.Phase == clientstate.AuthPending {
		footer = "resume: tnl auth login wait " + op.ID
	}
	return writeHumanFrame(output, command, strings.ReplaceAll(string(op.Phase), "_", " "), footer, clioutput.Fields(fields...))
}

func interactiveBrowserOpener(input io.Reader) func(string) error {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil
	}
	return openBrowser
}

func runLogout(ctx context.Context, flags logoutCommand, output io.Writer, diagnostics ...io.Writer) error {
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	diagnostic := io.Discard
	if len(diagnostics) != 0 && diagnostics[0] != nil {
		diagnostic = diagnostics[0]
	}
	if err := clientauth.Logout(ctx, clientauth.Config{
		ServerEndpoint: serverURL, State: state, Diagnostics: diagnostic,
	}); err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			Server        string `json:"server"`
			Status        string `json:"status"`
		}{1, serverURL, "logged_out"})
	}
	return writeHumanFrame(output, "tnl auth logout", "logged out", "local session removed",
		clioutput.Fields(clioutput.Field{Label: "control", Value: serverURL}),
	)
}
