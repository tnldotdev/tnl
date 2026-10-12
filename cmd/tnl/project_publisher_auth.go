package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
)

func publisherAuthClient(ctx context.Context, project projectConfiguration, selectedServer string, timeout time.Duration) (namedPublisherClient, error) {
	endpoint, err := remotePublisherScope(ctx, project, false, false, "")
	if err != nil {
		return namedPublisherClient{}, err
	}
	client := namedPublisherClient{endpoint: endpoint, http: publisherHTTPClient(timeout)}
	var status clientauth.StatusResult
	if err := client.request(ctx, http.MethodGet, "/v1/auth/status", "", nil, &status); err != nil {
		return namedPublisherClient{}, err
	}
	if selectedServer != "" {
		server, err := clientstate.CanonicalServer(selectedServer)
		if err != nil {
			return namedPublisherClient{}, err
		}
		if status.Server != server {
			return namedPublisherClient{}, failure.Wrap("select publisher login server", failure.ProjectConfigInvalid,
				errors.New("the selected publisher uses another control URL; update the project server first"))
		}
	}
	return client, nil
}

func runPublisherLogin(ctx context.Context, project projectConfiguration, flags loginCommand, input io.Reader, output, diagnostics io.Writer) error {
	if flags.Timeout < time.Second || flags.Timeout > 10*time.Minute {
		return failure.Wrap("wait for project publisher login", failure.InvalidCommand, errors.New("timeout must be between one second and ten minutes"))
	}
	client, err := publisherAuthClient(ctx, project, flags.ServerURL, flags.Timeout+20*time.Second)
	if err != nil {
		return err
	}
	tokenInput := os.Getenv("TNL_LOGIN_TOKEN")
	useLoginToken := tokenInput != "" || flags.LoginToken
	if !useLoginToken {
		var operation clientstate.AuthOperation
		err = client.request(ctx, http.MethodPost, "/v1/auth/login/start", "", nil, &operation)
		if err == nil {
			if err := writeAuthOperation(diagnostics, "tnl auth login", operation, flags.Output); err != nil {
				return err
			}
			if flags.Open && flags.Output != statusOutputJSON {
				if open := interactiveBrowserOpener(input); open != nil {
					_ = open(operation.ApprovalURL)
				}
			}
			err = client.request(ctx, http.MethodPost, "/v1/auth/login/wait", "", struct {
				ID             string `json:"operation_id"`
				TimeoutSeconds int    `json:"timeout_seconds"`
			}{operation.ID, int(flags.Timeout.Seconds())}, &operation)
			if err != nil {
				return err
			}
		} else if reason, ok := failure.ReasonOf(err); !ok || reason != failure.AuthMethodUnavailable {
			return err
		}
		if err == nil {
			return readPublisherLoginStatus(ctx, client, output, "tnl auth login", flags.Output)
		}
	}
	var token credentials.LoginToken
	if tokenInput != "" {
		token, err = parseLoginInput([]byte(tokenInput))
	} else if prompt := loginTokenPrompt(input, diagnostics); prompt != nil {
		token, err = prompt()
	} else {
		return failure.Wrap("log in to project publisher", failure.LoginTerminalRequired, errors.New("login token needs a terminal or TNL_LOGIN_TOKEN"))
	}
	if err != nil {
		return err
	}
	var status clientauth.StatusResult
	if err := client.request(ctx, http.MethodPost, "/v1/auth/login/token", "", struct {
		Token string `json:"token"`
	}{string(token)}, &status); err != nil {
		return err
	}
	if status.Status == "available" && status.Source == "saved_session" {
		status.Status = "authenticated"
	}
	return writeAuthStatus(output, "tnl auth login", status, flags.Output)
}

func readPublisherLoginStatus(ctx context.Context, client namedPublisherClient, output io.Writer, command string, mode statusOutputMode) error {
	var status clientauth.StatusResult
	if err := client.request(ctx, http.MethodGet, "/v1/auth/status", "", nil, &status); err != nil {
		return err
	}
	if status.Status == "available" && status.Source == "saved_session" {
		status.Status = "authenticated"
	}
	return writeAuthStatus(output, command, status, mode)
}

func runPublisherAuthStatus(ctx context.Context, project projectConfiguration, flags authStatusCommand, output io.Writer) error {
	client, err := publisherAuthClient(ctx, project, flags.ServerURL, 10*time.Second)
	if err != nil {
		return err
	}
	path := "/v1/auth/status"
	if flags.Check {
		path += "?check=1"
	}
	var status clientauth.StatusResult
	if err := client.request(ctx, http.MethodGet, path, "", nil, &status); err != nil {
		return err
	}
	return writeAuthStatus(output, "tnl auth status", status, flags.Output)
}

func runPublisherLogout(ctx context.Context, project projectConfiguration, flags logoutCommand, output io.Writer) error {
	client, err := publisherAuthClient(ctx, project, flags.ServerURL, 10*time.Second)
	if err != nil {
		return err
	}
	if err := client.request(ctx, http.MethodPost, "/v1/auth/logout", "", nil, nil); err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		var status clientauth.StatusResult
		if err := client.request(ctx, http.MethodGet, "/v1/auth/status", "", nil, &status); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			Server        string `json:"server"`
			Status        string `json:"status"`
		}{1, status.Server, "logged_out"})
	}
	return writeHumanFrame(output, "tnl auth logout", "logged out", "publisher session removed")
}

func runPublisherLoginOperation(ctx context.Context, project projectConfiguration, flags loginCommand, id, action string, output, diagnostics io.Writer) error {
	if flags.Timeout < time.Second || flags.Timeout > 10*time.Minute {
		return failure.Wrap("wait for project publisher login", failure.InvalidCommand, errors.New("timeout must be between one second and ten minutes"))
	}
	client, err := publisherAuthClient(ctx, project, flags.ServerURL, flags.Timeout+20*time.Second)
	if err != nil {
		return err
	}
	var operation clientstate.AuthOperation
	switch action {
	case "start":
		err = client.request(ctx, http.MethodPost, "/v1/auth/login/start", "", nil, &operation)
	case "wait":
		err = client.request(ctx, http.MethodPost, "/v1/auth/login/wait", "", struct {
			ID             string `json:"operation_id"`
			TimeoutSeconds int    `json:"timeout_seconds"`
		}{id, int(flags.Timeout.Seconds())}, &operation)
	case "inspect", "cancel":
		method := http.MethodGet
		if action == "cancel" {
			method = http.MethodDelete
		}
		err = client.request(ctx, method, "/v1/auth/login/"+url.PathEscape(id), "", nil, &operation)
	default:
		return failure.Wrap("observe publisher login", failure.InvalidCommand, errors.New("invalid login operation"))
	}
	if err != nil {
		return err
	}
	if action == "wait" && flags.Output != statusOutputJSON && operation.Phase == clientstate.AuthPending {
		if err := writeAuthOperation(diagnostics, "tnl auth login wait", operation, statusOutputHuman); err != nil {
			return err
		}
	}
	return writeAuthOperation(output, "tnl auth login "+action, operation, flags.Output)
}
