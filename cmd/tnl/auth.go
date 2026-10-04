package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"golang.org/x/term"
)

func runLogin(ctx context.Context, flags loginCommand, input io.Reader, output, errorOutput io.Writer) error {
	serverValue := flags.Server
	if serverValue == "" {
		serverValue = flags.ServerURL
	}
	serverURL, state, err := resolveServer(ctx, flags.StateDir, serverValue)
	if err != nil {
		return err
	}
	defer state.Close()
	prompt := loginTokenPrompt(input, errorOutput)
	if flags.LoginToken != "" {
		token, err := parseLoginInput([]byte(flags.LoginToken))
		if err != nil {
			return err
		}
		prompt = func() (credentials.LoginToken, error) { return token, nil }
	}
	authenticated, err := clientauth.Authenticate(ctx, clientauth.Config{
		ServerEndpoint: serverURL, State: state, Diagnostics: errorOutput,
		LoginToken: prompt, AuthenticationPrompt: authenticationPrompt(errorOutput, "tnl login"),
		OpenURL:    interactiveBrowserOpener(input),
		ForceLogin: true, ForceLoginToken: flags.Token,
	})
	if err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl login", "authenticated", "saved for future commands",
		clioutput.Fields(clioutput.Field{Label: "control", Value: authenticated.ServerEndpoint}),
	)
}

func readLoginToken(input io.Reader, output io.Writer) (credentials.LoginToken, error) {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return "", failure.Wrap("read login token", failure.LoginTerminalRequired,
			errors.New("login-token authentication requires an interactive terminal"))
	}
	if _, err := fmt.Fprint(output, "Login token: "); err != nil {
		return "", err
	}
	data, err := term.ReadPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(output)
	if err != nil {
		return "", fmt.Errorf("read login token: %w", err)
	}
	return parseLoginInput(data)
}

func loginTokenPrompt(input io.Reader, output io.Writer) func() (credentials.LoginToken, error) {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil
	}
	return func() (credentials.LoginToken, error) { return readLoginToken(input, output) }
}

func interactiveBrowserOpener(input io.Reader) func(string) error {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil
	}
	return openBrowser
}

func parseLoginInput(data []byte) (credentials.LoginToken, error) {
	token := credentials.LoginToken(strings.TrimSpace(string(data)))
	if _, err := credentials.ParseLoginToken(token); err != nil {
		return "", failure.Wrap("validate login token", failure.LoginTokenInvalid, err)
	}
	return token, nil
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
	return writeHumanFrame(output, "tnl logout", "logged out", "local session removed",
		clioutput.Fields(clioutput.Field{Label: "control", Value: serverURL}),
	)
}
