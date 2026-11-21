package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/cliflags"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"golang.org/x/term"
)

type authCommand struct {
	Credential authCredentialCommand
	Status     authStatusCommand
	Login      authLoginCommand
	Logout     logoutCommand
	Browser    authBrowserCommand
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
	Run          struct{}
	Start        struct{}
	Wait         authOperationCommand
	Inspect      authOperationCommand
	Cancel       authOperationCommand
}

type authOperationCommand struct {
	ID string `arg:"" name:"operation-id" help:"Operation ID returned by auth login start."`
}

type logoutCommand struct {
	ServerURL string           `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the project or selected server."`
	StateDir  string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Output    statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

func authLoginConfig(flags loginCommand, server string, state *clientstate.Database, input io.Reader, diagnostics io.Writer) (auth.Config, error) {
	config := auth.Config{ServerEndpoint: server, State: state, Diagnostics: diagnostics,
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
	_, err = auth.Login(ctx, config)
	if err != nil {
		return err
	}
	return writeLoginResult(ctx, config, output, flags.Output)
}

func writeLoginResult(ctx context.Context, config auth.Config, output io.Writer, mode statusOutputMode) error {
	status, err := auth.Status(ctx, config, false)
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
	op, err := auth.StartLogin(ctx, config)
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
	config := auth.Config{ServerEndpoint: server, State: state, Diagnostics: diagnostics}
	var op clientstate.AuthOperation
	switch action {
	case "wait":
		if flags.Output != statusOutputJSON {
			pending, inspectErr := auth.InspectLogin(ctx, config, id)
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
		op, err = auth.WaitLogin(ctx, config, id, flags.Timeout)
	case "inspect":
		op, err = auth.InspectLogin(ctx, config, id)
	case "cancel":
		op, err = auth.CancelLogin(ctx, config, id)
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
	status, err := auth.Status(ctx, auth.Config{ServerEndpoint: server, State: state, AccessToken: flags.AccessToken, Diagnostics: diagnostics}, flags.Check)
	if err != nil {
		return err
	}
	return writeAuthStatus(output, "tnl auth status", status, flags.Output)
}

func writeAuthStatus(output io.Writer, command string, status auth.StatusResult, mode statusOutputMode) error {
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
	if err := auth.Logout(ctx, auth.Config{
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

func (a *commandApp) newAuthCommand() *cobra.Command {
	f := a.flags
	cAuth := &cobra.Command{Use: "auth", Short: "Inspect credentials and explicitly log in or out.", GroupID: "manage"}
	cAuthCredential := &cobra.Command{Use: "credential", Short: "Create a scoped signing credential for a deployment backend."}
	cAuthCredentialCreate := &cobra.Command{Use: "create", Short: "Approve independent deployment management, connection, and publication capabilities."}
	a.leaf(cAuthCredentialCreate, &f.Auth.Credential.Create, func(call commandCall) error {
		return runAuthCredentialCreate(call.ctx, f.Auth.Credential.Create, call.project, a.out, a.errOut)
	})
	cAuthCredential.AddCommand(cAuthCredentialCreate)
	cAuth.AddCommand(cAuthCredential)
	cAuthStatus := &cobra.Command{Use: "status", Short: "Show local credentials; --check silently validates with the server."}
	a.leaf(cAuthStatus, &f.Auth.Status, func(call commandCall) error {
		return runAuthStatus(call.ctx, f.Auth.Status, a.out, a.errOut)
	})
	cAuth.AddCommand(cAuthStatus)
	cAuthLogin := &cobra.Command{Use: "login", Short: "Log in explicitly, or manage a resumable login operation."}
	cliflags.Bind(cAuthLogin, &f.Auth.Login.loginCommand, true)
	cAuthLoginRun := &cobra.Command{Use: "run", Short: "", Hidden: true}
	a.leaf(cAuthLoginRun, &f.Auth.Login.Run, func(call commandCall) error {
		return runLogin(call.ctx, f.Auth.Login.loginCommand, os.Stdin, a.out, a.errOut)
	})
	cAuthLogin.AddCommand(cAuthLoginRun)
	a.useDefault(cAuthLogin, cAuthLoginRun)
	cAuthLoginStart := &cobra.Command{Use: "start", Short: "Return a pending device login operation immediately."}
	a.leaf(cAuthLoginStart, &f.Auth.Login.Start, func(call commandCall) error {
		return runAuthLoginStart(call.ctx, f.Auth.Login.loginCommand, os.Stdin, a.out, a.errOut)
	})
	cAuthLogin.AddCommand(cAuthLoginStart)
	cAuthLoginWait := &cobra.Command{Use: "wait", Short: "Wait for approval and save credentials for this operation."}
	a.leaf(cAuthLoginWait, &f.Auth.Login.Wait, func(call commandCall) error {
		return runAuthLoginOperation(call.ctx, f.Auth.Login.loginCommand, f.Auth.Login.Wait.ID, "wait", a.out, a.errOut)
	})
	cAuthLogin.AddCommand(cAuthLoginWait)
	cAuthLoginInspect := &cobra.Command{Use: "inspect", Short: "Show the current state of a saved login attempt."}
	a.leaf(cAuthLoginInspect, &f.Auth.Login.Inspect, func(call commandCall) error {
		return runAuthLoginOperation(call.ctx, f.Auth.Login.loginCommand, f.Auth.Login.Inspect.ID, "inspect", a.out, a.errOut)
	})
	cAuthLogin.AddCommand(cAuthLoginInspect)
	cAuthLoginCancel := &cobra.Command{Use: "cancel", Short: "Cancel this login attempt so it cannot save a session."}
	a.leaf(cAuthLoginCancel, &f.Auth.Login.Cancel, func(call commandCall) error {
		return runAuthLoginOperation(call.ctx, f.Auth.Login.loginCommand, f.Auth.Login.Cancel.ID, "cancel", a.out, a.errOut)
	})
	cAuthLogin.AddCommand(cAuthLoginCancel)
	cAuth.AddCommand(cAuthLogin)
	cAuthLogout := &cobra.Command{Use: "logout", Short: "Cancel login operations and remove the saved control session."}
	a.leaf(cAuthLogout, &f.Auth.Logout, func(call commandCall) error {
		return runLogout(call.ctx, f.Auth.Logout, a.out, a.errOut)
	})
	cAuth.AddCommand(cAuthLogout)
	cAuthBrowser := &cobra.Command{Use: "browser", Short: "Sign in to visit an HTTP public URL in a browser."}
	a.leaf(cAuthBrowser, &f.Auth.Browser, func(call commandCall) error {
		return runAuthBrowser(call.ctx, f.Auth.Browser, a.out, a.errOut)
	})
	cAuth.AddCommand(cAuthBrowser)
	return cAuth
}
