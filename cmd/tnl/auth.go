package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/cliflags"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
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
	projectServer *string
	configArgs    string
	Team          string           `name:"team" help:"Team name to authenticate for; defaults to the project or saved team."`
	ServerURL     string           `name:"server" env:"TNL_SERVER" help:"Control URL. Defaults to the project or selected server."`
	StateDir      string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	Open          bool             `name:"open" help:"Open the approval URL in a browser."`
	Timeout       time.Duration    `name:"timeout" default:"10m" help:"Maximum wait; a device login operation can be resumed after timeout."`
	Output        statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
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

func authLoginConfig(flags loginCommand, server string, state *clientstate.Database, input io.Reader, diagnostics io.Writer) auth.Config {
	config := auth.Config{ServerEndpoint: server, State: state, Diagnostics: diagnostics,
		Team:                 flags.Team,
		LoginTimeout:         flags.Timeout,
		AuthenticationPrompt: authenticationPrompt(diagnostics, "tnl auth login")}
	if flags.Open && flags.Output != statusOutputJSON {
		config.OpenURL = interactiveBrowserOpener(input)
	}
	return config
}

func runLogin(ctx context.Context, flags loginCommand, input io.Reader, output, errorOutput io.Writer) error {
	serverURL, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	config := authLoginConfig(flags, serverURL, state, input, errorOutput)
	var id string
	config.ObserveLogin = func(op clientstate.AuthOperation) error {
		id = op.ID
		return writeWaitingLogin(errorOutput, op, flags.Output, config.OpenURL != nil && op.Phase == clientstate.AuthPending)
	}
	_, err = auth.Login(ctx, config)
	if err != nil {
		return interruptedLogin(ctx, config, id, flags, errorOutput, err)
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
		if mode != statusOutputJSON {
			return writeSignedIn(output, status.Server)
		}
	}
	return writeAuthStatus(output, status, mode)
}

func runAuthLoginStart(ctx context.Context, flags loginCommand, input io.Reader, output, diagnostics io.Writer) error {
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	config := authLoginConfig(flags, server, state, input, diagnostics)
	op, err := auth.StartLogin(ctx, config)
	if err != nil {
		return err
	}
	return writeAuthOperation(output, op, flags.Output, flags.resumeCommand(ctx, state, op))
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
			if loginNeedsApproval(pending) {
				var open func(string) error
				if flags.Open {
					open = interactiveBrowserOpener(os.Stdin)
				}
				if err := writeWaitingLogin(diagnostics, pending, flags.Output, open != nil); err != nil {
					return err
				}
				if open != nil {
					_ = open(pending.ApprovalURL)
				}
			}
		}
		op, err = auth.WaitLogin(ctx, config, id, flags.Timeout)
		if err != nil {
			return interruptedLogin(ctx, config, id, flags, diagnostics, err)
		}
		if flags.Output != statusOutputJSON && op.Phase == clientstate.AuthCompleted {
			return writeSignedIn(output, op.Server)
		}
	case "inspect":
		op, err = auth.InspectLogin(ctx, config, id)
	case "cancel":
		op, err = auth.CancelLogin(ctx, config, id)
	}
	if err != nil {
		return err
	}
	return writeAuthOperation(output, op, flags.Output, flags.resumeCommand(ctx, state, op))
}

func loginNeedsApproval(op clientstate.AuthOperation) bool {
	return (op.Phase == clientstate.AuthPending || op.Phase == clientstate.AuthExchanging) && op.ApprovalURL != "" && op.ExpiresAt.After(time.Now())
}

func writeWaitingLogin(output io.Writer, op clientstate.AuthOperation, mode statusOutputMode, opening bool) error {
	if mode == statusOutputJSON || !loginNeedsApproval(op) {
		return writeAuthOperation(output, op, mode, "")
	}
	blocks := approvalBlocks(op.ApprovalURL, op.UserCode, opening)
	return writeResult(output, append(blocks, clioutput.Text("Waiting for approval..."))...)
}

func writeSignedIn(output io.Writer, server string) error {
	if server == defaultServerURL {
		return writeResult(output, clioutput.Text("Signed in."))
	}
	return writeResult(output, clioutput.Line("Signed in to "+server))
}

func (flags loginCommand) resumeCommand(ctx context.Context, state *clientstate.Database, op clientstate.AuthOperation) string {
	if flags.Output == statusOutputJSON || op.Method != "device_code" || !(loginNeedsApproval(op) || op.Phase == clientstate.AuthIssued) {
		return ""
	}
	cmd := "tnl " + flags.configArgs + "auth login wait " + shellWord(op.ID)
	if pin := suggestedServer(ctx, op.Server, flags.projectServer, "", flags.StateDir, state); pin != "" {
		cmd += " --server=" + shellWord(pin)
	}
	if flags.StateDir != "" {
		cmd += " --state-dir=" + shellWord(flags.StateDir)
	}
	return cmd
}

func interruptedLogin(ctx context.Context, config auth.Config, id string, flags loginCommand, diagnostics io.Writer, cause error) error {
	if id == "" || flags.Output == statusOutputJSON || !(ctx.Err() != nil || errors.Is(cause, context.DeadlineExceeded)) {
		return cause
	}
	// read the durable phase: cancellation can race with exchange or installation.
	inspectCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	op, err := auth.InspectLogin(inspectCtx, config, id)
	if err == nil {
		if cmd := flags.resumeCommand(inspectCtx, config.State, op); cmd != "" {
			if reason, _ := failure.ReasonOf(cause); reason == failure.AuthWaitTimeout {
				return &loginTimeout{cause, cmd}
			}
			return errors.Join(cause, writeResult(diagnostics,
				clioutput.Text("Resume login:"), clioutput.Literal(cmd)))
		}
	}
	return cause
}

type loginTimeout struct {
	cause  error
	resume string
}

func (e *loginTimeout) Error() string { return e.cause.Error() }
func (e *loginTimeout) Unwrap() error { return e.cause }

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
	return writeAuthStatus(output, status, flags.Output)
}

func writeAuthStatus(output io.Writer, status auth.StatusResult, mode statusOutputMode) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(status)
	}
	var summary string
	switch status.Status {
	case "unauthenticated":
		summary = "Not signed in to " + status.Server
	case "authenticated":
		summary = "Signed in to " + status.Server
	case "available":
		summary = "Saved session for " + status.Server + " (not checked)"
		if status.Source == "explicit_access_token" {
			summary = "Access token supplied for " + status.Server + " (not checked)"
		}
	case "refresh_required":
		summary = "Session needs a refresh: " + status.Server
	case "expired":
		summary = "Session expired: " + status.Server
	case "recovery_required":
		summary = "Session needs a new login: " + status.Server
	default:
		summary = strings.ReplaceAll(status.Status, "_", " ") + ": " + status.Server
	}
	return writeResult(output, clioutput.Line(summary))
}

func writeAuthOperation(output io.Writer, op clientstate.AuthOperation, mode statusOutputMode, resume string) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int `json:"schema_version"`
			clientstate.AuthOperation
		}{1, op})
	}
	blocks := []clioutput.Block{}
	if loginNeedsApproval(op) {
		blocks = approvalBlocks(op.ApprovalURL, op.UserCode, false)
	} else if op.Phase == clientstate.AuthCompleted {
		blocks = append(blocks, clioutput.Line("Login completed on "+op.Server))
	} else {
		blocks = append(blocks, clioutput.Line("Login "+strings.ReplaceAll(string(op.Phase), "_", " ")+": "+op.Server))
	}
	if resume != "" {
		label := "Finish login:"
		if loginNeedsApproval(op) {
			label = "Finish login before " + op.ExpiresAt.UTC().Format("15:04 MST") + ":"
		}
		blocks = append(blocks, clioutput.Text(label), clioutput.Literal(resume))
	}
	return writeResult(output, blocks...)
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
	return writeResult(output, clioutput.Line("Signed out of "+serverURL))
}

func (a *commandApp) newAuthCommand() *cobra.Command {
	f := a.flags
	loginFlags := func(call commandCall) loginCommand {
		flags := f.Auth.Login.loginCommand
		flags.projectServer = call.project.Config.Server
		flags.configArgs = configArgs(f.NoConfig, f.ConfigPath)
		return flags
	}
	cAuth := &cobra.Command{Use: "auth", Short: "Sign in, check your session, or sign out.", GroupID: "start"}
	cAuthCredential := &cobra.Command{Use: "credential", Short: "Create a scoped signing credential for a deployment backend."}
	cAuthCredentialCreate := &cobra.Command{Use: "create", Short: "Issue a credential for the services and actions you select."}
	a.leaf(cAuthCredentialCreate, &f.Auth.Credential.Create, func(call commandCall) error {
		return runAuthCredentialCreate(call.ctx, f.Auth.Credential.Create, call.project, a.out, a.errOut)
	})
	cAuthCredential.AddCommand(cAuthCredentialCreate)
	cAuth.AddCommand(cAuthCredential)
	cAuthStatus := &cobra.Command{Use: "status", Short: "Show your sign-in status. Use --check to contact the server."}
	a.leaf(cAuthStatus, &f.Auth.Status, func(call commandCall) error {
		return runAuthStatus(call.ctx, f.Auth.Status, a.out, a.errOut)
	})
	cAuth.AddCommand(cAuthStatus)
	cAuthLogin := &cobra.Command{
		Use: "login", Short: "Sign in to the tnl server.",
		Long: "Follow the approval URL to sign in. For scripts, use start to get an operation ID, then wait with that ID to save the approved session.",
	}
	cliflags.Bind(cAuthLogin, &f.Auth.Login.loginCommand, true)
	cAuthLoginRun := &cobra.Command{Use: "run", Short: "", Hidden: true}
	a.leaf(cAuthLoginRun, &f.Auth.Login.Run, func(call commandCall) error {
		return runLogin(call.ctx, loginFlags(call), os.Stdin, a.out, a.errOut)
	})
	cAuthLogin.AddCommand(cAuthLoginRun)
	a.useDefault(cAuthLogin, cAuthLoginRun)
	cAuthLoginStart := &cobra.Command{Use: "start", Short: "Print an approval URL and operation ID without waiting."}
	a.leaf(cAuthLoginStart, &f.Auth.Login.Start, func(call commandCall) error {
		return runAuthLoginStart(call.ctx, loginFlags(call), os.Stdin, a.out, a.errOut)
	})
	cAuthLogin.AddCommand(cAuthLoginStart)
	cAuthLoginWait := &cobra.Command{Use: "wait", Short: "Wait for approval and save credentials for this operation."}
	a.leaf(cAuthLoginWait, &f.Auth.Login.Wait, func(call commandCall) error {
		return runAuthLoginOperation(call.ctx, loginFlags(call), f.Auth.Login.Wait.ID, "wait", a.out, a.errOut)
	})
	cAuthLogin.AddCommand(cAuthLoginWait)
	cAuthLoginInspect := &cobra.Command{Use: "inspect", Short: "Show the current state of a saved login attempt."}
	a.leaf(cAuthLoginInspect, &f.Auth.Login.Inspect, func(call commandCall) error {
		return runAuthLoginOperation(call.ctx, loginFlags(call), f.Auth.Login.Inspect.ID, "inspect", a.out, a.errOut)
	})
	cAuthLogin.AddCommand(cAuthLoginInspect)
	cAuthLoginCancel := &cobra.Command{Use: "cancel", Short: "Cancel this login attempt so it cannot save a session."}
	a.leaf(cAuthLoginCancel, &f.Auth.Login.Cancel, func(call commandCall) error {
		return runAuthLoginOperation(call.ctx, loginFlags(call), f.Auth.Login.Cancel.ID, "cancel", a.out, a.errOut)
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
