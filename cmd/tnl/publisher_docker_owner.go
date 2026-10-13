package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/dockertarget"
	"github.com/tnldotdev/tnl/internal/failure"
)

const maxOwnerRequestBytes = 256 << 10

type dockerOwnerRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Owner  string          `json:"owner,omitempty"`
	Body   json.RawMessage `json:"body,omitempty"`
}

type dockerOwnerResponse struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Body        []byte `json:"body,omitempty"`
}

// runRuntimeOwner executes one bounded owner-authorized request inside the
// publisher container. the owner credential stays in its private client state.
func runRuntimeOwner(ctx context.Context, options runtimeOptions, input io.Reader, output io.Writer) error {
	project, root, err := runtimeProject(ctx, options)
	if err != nil {
		return err
	}
	if project.Config.Publisher == nil || project.Config.Publisher.Type != "docker" {
		return failure.Wrap("select Docker publisher", failure.ProjectConfigInvalid, errors.New("owner requests require a Docker publisher"))
	}
	var request dockerOwnerRequest
	raw, err := io.ReadAll(io.LimitReader(input, maxOwnerRequestBytes+1))
	if err != nil || len(raw) > maxOwnerRequestBytes {
		return failure.Wrap("read publisher owner request", failure.InvalidCommand, errors.New("owner request exceeds limit"))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return failure.Wrap("read publisher owner request", failure.InvalidCommand, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return failure.Wrap("read publisher owner request", failure.InvalidCommand, errors.New("trailing owner request data"))
	}
	parsed, err := url.ParseRequestURI(request.Path)
	if err != nil || !strings.HasPrefix(request.Path, "/v1/") || parsed.IsAbs() || parsed.Host != "" ||
		request.Method != http.MethodGet && request.Method != http.MethodPost && request.Method != http.MethodDelete || len(request.Body) > maxOwnerRequestBytes {
		return failure.Wrap("validate publisher owner request", failure.InvalidCommand, errors.New("invalid local publisher request"))
	}
	key, err := runtimeKey(project.Root, root)
	if err != nil {
		return err
	}
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		return err
	}
	var body io.Reader
	if len(request.Body) != 0 {
		body = bytes.NewReader(request.Body)
	}
	upstream, err := http.NewRequestWithContext(ctx, request.Method, endpoint.URL+request.Path, body)
	if err != nil {
		return err
	}
	upstream.Header.Set("Authorization", "Bearer "+endpoint.Credential)
	if body != nil {
		upstream.Header.Set("Content-Type", "application/json")
	}
	if request.Owner != "" {
		upstream.Header.Set("X-Publication-Owner", request.Owner)
	}
	response, err := publisherHTTPClient(0).Do(upstream)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxOwnerRequestBytes+1))
	if err != nil || len(data) > maxOwnerRequestBytes {
		return failure.Wrap("read Docker publisher", failure.ServerResponseInvalid, errors.New("publisher response exceeds limit"))
	}
	return json.NewEncoder(output).Encode(dockerOwnerResponse{Status: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: data})
}

type dockerOwnerTransport struct {
	container string
	directory string
}

type boundedOwnerOutput struct {
	bytes.Buffer
}

func (b *boundedOwnerOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 2*maxOwnerRequestBytes {
		return 0, errors.New("Docker publisher response exceeds limit")
	}
	return b.Buffer.Write(data)
}

func (t dockerOwnerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if ip := net.ParseIP(request.URL.Hostname()); ip == nil || !ip.IsLoopback() || !strings.HasPrefix(request.URL.Path, "/v1/") {
		return nil, errors.New("invalid Docker publisher request")
	}
	var body []byte
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(request.Body, maxOwnerRequestBytes+1))
		if err != nil || len(body) > maxOwnerRequestBytes {
			return nil, errors.New("Docker publisher request exceeds limit")
		}
	}
	encoded, err := json.Marshal(dockerOwnerRequest{Method: request.Method, Path: request.URL.RequestURI(), Owner: request.Header.Get("X-Publication-Owner"), Body: body})
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(request.Context(), "docker", "exec", "-i", t.container, "tnl", "runtime", "owner", "--directory", t.directory)
	command.Stdin = bytes.NewReader(encoded)
	command.Stderr = io.Discard
	var output boundedOwnerOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("request Docker publisher: %w", err)
	}
	if output.Len() > 2*maxOwnerRequestBytes {
		return nil, errors.New("Docker publisher response exceeds limit")
	}
	var result dockerOwnerResponse
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Status < 100 || result.Status > 599 || len(result.Body) > maxOwnerRequestBytes {
		return nil, errors.New("invalid Docker publisher response")
	}
	return &http.Response{StatusCode: result.Status, Header: http.Header{"Content-Type": []string{result.ContentType}},
		Body: io.NopCloser(bytes.NewReader(result.Body)), Request: request}, nil
}

func dockerPublisherClient(ctx context.Context, project projectConfiguration, timeout time.Duration) (namedPublisherClient, error) {
	selection := project.Config.Publisher
	if selection == nil || selection.Type != "docker" {
		return namedPublisherClient{}, errors.New("the project does not use a Docker publisher")
	}
	container, err := dockertarget.SelectContainer(ctx, project.Root, project.Worktree.Label.FullLabel, selection.DockerSelection)
	if err != nil {
		return namedPublisherClient{}, failure.Wrap("select Docker publisher", failure.ClientStateUnavailable, err)
	}
	address, err := dockertarget.HostPort(container, *selection.ContainerPort, true)
	if err != nil {
		return namedPublisherClient{}, failure.Wrap("connect to Docker publisher", failure.ClientStateUnavailable, err)
	}
	return namedPublisherClient{endpoint: localPublisherEndpoint{URL: "http://" + address},
		http: &http.Client{Timeout: timeout, Transport: dockerOwnerTransport{container: container.Name, directory: project.Root}}}, nil
}
