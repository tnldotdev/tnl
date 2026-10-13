package localpublisher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

const maxNamedPublisherResponse = 256 << 10

var ErrUnauthenticated = errors.New("local publisher credential is no longer current")
var ErrLost = errors.New("local publisher stopped")

type namedPublisherClient struct {
	endpoint Endpoint
	http     *http.Client
}

func (c namedPublisherClient) request(ctx context.Context, method, path, owner string, body, value any) error {
	return Request(ctx, c.http, c.endpoint, method, path, owner, body, value)
}

func Request(ctx context.Context, client *http.Client, endpoint Endpoint, method, path, owner string, body, value any) error {
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		input = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint.URL+path, input)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if owner != "" {
		request.Header.Set("X-Publication-Owner", owner)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxNamedPublisherResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxNamedPublisherResponse {
		return failure.Wrap("read local publisher", failure.ServerResponseInvalid, errors.New("local publisher response exceeds 256 KiB"))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var problem localpublisherv1.Problem
		if json.Unmarshal(data, &problem) != nil || problem.Code == "" {
			return failure.Wrap("request local publisher", failure.ServerResponseInvalid, errors.New("local publisher rejected the request"))
		}
		if response.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("%w: %s", ErrUnauthenticated, problem.Message)
		}
		if problem.Code == "runtime.registration_stale" && strings.HasPrefix(path, "/v1/publications/") {
			return fmt.Errorf("%w: %s", ErrLost, problem.Message)
		}
		if problem.Code == string(failure.AuthMethodUnavailable) {
			return failure.Wrap("select publisher login method", failure.AuthMethodUnavailable, errors.New(problem.Message))
		}
		if problem.Code == string(failure.AuthWaitTimeout) {
			return failure.Wrap("wait for publisher login", failure.AuthWaitTimeout, errors.New(problem.Message))
		}
		if problem.Code == string(failure.AuthOperationNotFound) {
			return failure.Wrap("find publisher login", failure.AuthOperationNotFound, errors.New(problem.Message))
		}
		return fmt.Errorf("%s: %s", problem.Code, problem.Message)
	}
	if value == nil {
		if response.StatusCode != http.StatusNoContent || len(data) != 0 {
			return failure.Wrap("read local publisher", failure.ServerResponseInvalid, errors.New("local publisher returned an unexpected response"))
		}
		return nil
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" || json.Unmarshal(data, value) != nil {
		return failure.Wrap("read local publisher", failure.ServerResponseInvalid, errors.New("local publisher returned invalid JSON"))
	}
	return nil
}
