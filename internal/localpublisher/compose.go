package localpublisher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

// ComposeOwner is selected from host configuration, never inferred from a
// container name. exec carries requests over stdin and never exports owner caps.
type ComposeOwner struct {
	Docker        publishertarget.Runner
	HostRoot      string
	Project       string
	File          string
	Service       string
	ContainerRoot string
	ContainerID   string
	Worktree      projectconfig.Worktree
}

type ComposeQuery struct {
	Method     string                             `json:"method"`
	Path       string                             `json:"path"`
	Body       json.RawMessage                    `json:"body,omitempty"`
	Capability *privateprotocol.CapabilityRequest `json:"capability,omitempty"`
}

type ComposeReply struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

func (o ComposeOwner) Configure(ctx context.Context, setup ComposeSetup) error {
	docker := o.Docker
	if docker == nil {
		docker = publishertarget.CLI{}
	}
	if err := setup.Validate(ctx, docker); err != nil {
		return err
	}
	if setup.Project != o.Project || setup.File != o.File || setup.Service != o.Service || setup.ProjectRoot != o.ContainerRoot || o.ContainerID != "" && setup.Placement.OwnerID != o.ContainerID || setup.Placement.ProjectRoot != o.HostRoot || setup.Placement.Worktree.Label.FullLabel != o.Worktree.Label.FullLabel {
		return errors.New("compose setup does not match selected owner")
	}
	input, err := json.Marshal(setup)
	if err != nil || len(input) > privateprotocol.MaxBytes {
		return errors.New("compose setup exceeds size limit")
	}
	args := publishertarget.ComposeArgs(o.HostRoot, o.File, o.Project)
	args = append(args, "exec", "--no-TTY", "--interactive", "--index", "1", o.Service, "tnl", "runtime", "serve", "--compose-configure", "--directory", o.ContainerRoot)
	_, err = docker.Run(ctx, input, args...)
	return err
}

func (o ComposeOwner) Call(ctx context.Context, query ComposeQuery) (ComposeReply, error) {
	docker := o.Docker
	if docker == nil {
		docker = publishertarget.CLI{}
	}
	if err := publishertarget.Local(ctx, docker); err != nil {
		return ComposeReply{}, err
	}
	container, err := publishertarget.ComposeContainer(ctx, docker, o.HostRoot, o.File, o.Project, o.Service, o.Worktree.Label.FullLabel)
	if err != nil {
		return ComposeReply{}, err
	}
	if o.ContainerID != "" && container.ID != o.ContainerID {
		return ComposeReply{}, ErrComposePlacementStale
	}
	if !filepath.IsAbs(o.ContainerRoot) || !validQuery(query) {
		return ComposeReply{}, errors.New("invalid compose owner query")
	}
	input, err := json.Marshal(query)
	if err != nil || len(input) > privateprotocol.MaxBytes {
		return ComposeReply{}, errors.New("compose owner query exceeds size limit")
	}
	args := publishertarget.ComposeArgs(o.HostRoot, o.File, o.Project)
	args = append(args, "exec", "--no-TTY", "--interactive", "--index", "1", o.Service, "tnl", "runtime", "serve", "--compose-request", "--directory", o.ContainerRoot)
	output, err := docker.Run(ctx, input, args...)
	if err != nil {
		return ComposeReply{}, err
	}
	var reply ComposeReply
	if len(output) > 8<<20 || strictJSON(output, &reply) != nil || reply.Status < 200 || reply.Status > 599 {
		return ComposeReply{}, errors.New("invalid compose owner response")
	}
	return reply, nil
}

func validQuery(q ComposeQuery) bool {
	if strings.ContainsAny(q.Path, "\r\n\\#") || !strings.HasPrefix(q.Path, "/v1/") || strings.Contains(q.Path, "..") || strings.Contains(q.Path, "%") {
		return false
	}
	u, err := url.ParseRequestURI(q.Path)
	return err == nil && !u.IsAbs() && u.Host == "" && (q.Method == "GET" || q.Method == "POST")
}

func strictJSON(data []byte, output any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(output); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

// ServeComposeQuery runs only inside docker compose exec. the endpoint is read
// inside the container and the owner credential is never part of its output.
func ServeComposeQuery(ctx context.Context, endpoint privateprotocol.Endpoint, input io.Reader, output io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(input, privateprotocol.MaxBytes+1))
	var query ComposeQuery
	if err != nil || len(data) > privateprotocol.MaxBytes || strictJSON(data, &query) != nil || !validQuery(query) || privateprotocol.ValidateEndpoint(endpoint) != nil || endpoint.Scope != "owner" {
		return errors.New("invalid compose owner query")
	}
	// an exec query must never turn into an owner-credential export endpoint.
	if query.Path != "/v1/health" && query.Path != "/v1/status" && query.Path != "/v1/prepare" && query.Path != "/v1/register" && query.Path != "/v1/renew" && query.Path != "/v1/unregister" && query.Path != "/v1/check" && query.Path != "/v1/leases" && query.Path != "/v1/ad-hoc/register" && query.Path != "/v1/capabilities" && !strings.HasPrefix(query.Path, "/v1/events?after=") {
		return privateprotocol.ErrForbidden
	}
	if query.Path == "/v1/capabilities" {
		var request privateprotocol.CapabilityRequest
		if strictJSON(query.Body, &request) != nil || request.Scope == "owner" {
			return privateprotocol.ErrForbidden
		}
	}
	if query.Capability != nil {
		if query.Capability.Scope != "app" && query.Capability.Scope != "invocation" {
			return privateprotocol.ErrForbidden
		}
		var scoped privateprotocol.Endpoint
		if err := privateprotocol.Call(ctx, endpoint, "POST", "/v1/capabilities", *query.Capability, &scoped); err != nil {
			return err
		}
		endpoint = scoped
	}
	request, err := http.NewRequestWithContext(ctx, query.Method, endpoint.Url+query.Path, bytes.NewReader(query.Body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+endpoint.Capability)
	if query.Method == "POST" {
		request.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil || len(body) > 8<<20 || len(body) != 0 && !json.Valid(body) {
		return errors.New("invalid compose owner response")
	}
	return json.NewEncoder(output).Encode(ComposeReply{Status: response.StatusCode, Body: body})
}

// Bridge exposes a host-loopback endpoint backed by exec queries. the host cap
// belongs to this bridge, not to the container. replacement is checked per call.
func (o ComposeOwner) Bridge(ctx context.Context) (privateprotocol.Endpoint, io.Closer, error) {
	if reply, err := o.Call(ctx, ComposeQuery{Method: "GET", Path: "/v1/health"}); err != nil || reply.Status != 204 {
		if ctx.Err() != nil {
			return privateprotocol.Endpoint{}, nil, ctx.Err()
		}
		return privateprotocol.Endpoint{}, nil, errors.New("compose publisher is not ready; start its configured service")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return privateprotocol.Endpoint{}, nil, err
	}
	caps, err := privateprotocol.NewCapabilities("http://" + listener.Addr().String())
	if err != nil {
		listener.Close()
		return privateprotocol.Endpoint{}, nil, err
	}
	handler := caps.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grant := privateprotocol.Grant(r)
		data, err := io.ReadAll(io.LimitReader(r.Body, privateprotocol.MaxBytes+1))
		if err != nil || len(data) > privateprotocol.MaxBytes {
			Problem(w, privateprotocol.ErrForbidden)
			return
		}
		query := ComposeQuery{Method: r.Method, Path: r.URL.RequestURI(), Body: data}
		if grant.Scope != "owner" {
			query.Capability = &privateprotocol.CapabilityRequest{Scope: "app", Service: grant.Service, InvocationId: grant.InvocationId}
			if grant.Scope == "invocation" {
				query.Capability.Scope = "invocation"
			}
		}
		// a local bridge capability stays local. the exec helper discovers the
		// corresponding app/invocation capability inside the owner on each call.
		if r.Method == "POST" && r.URL.RequestURI() == "/v1/capabilities" {
			if grant.Scope != "owner" {
				Problem(w, privateprotocol.ErrForbidden)
				return
			}
			var request privateprotocol.CapabilityRequest
			if strictJSON(data, &request) != nil || request.Scope == "owner" {
				Problem(w, privateprotocol.ErrForbidden)
				return
			}
			reply, err := o.Call(r.Context(), query)
			if err != nil || reply.Status != 200 {
				Problem(w, privateprotocol.ErrForbidden)
				return
			}
			endpoint, err := caps.Issue(request)
			if err != nil {
				Problem(w, err)
				return
			}
			privateprotocol.Write(w, 200, endpoint)
			return
		}
		reply, err := o.Call(r.Context(), query)
		if err != nil {
			privateprotocol.Write(w, 503, privateprotocol.Problem{Code: "runtime.owner_unavailable", Message: "start the configured compose publisher service"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(reply.Status)
		_, _ = w.Write(reply.Body)
	}))
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: privateprotocol.MaxBytes}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(listener)
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	return caps.Owner(), server, nil
}

type AppEndpointMount struct {
	Service   string
	Path      string
	Container publishertarget.Container
}

// WriteComposeAppEndpoints rotates app capabilities using directory mounts.
// each app gets one read-only named volume; no volume contains the owner cap.
func WriteComposeAppEndpoints(ctx context.Context, boundary ComposeBoundary, caps *privateprotocol.Capabilities, apps []AppEndpointMount) error {
	owner, err := publishertarget.Inspect(ctx, boundary.runner(), boundary.Placement.OwnerID)
	if err != nil {
		return err
	}
	if owner.Config.Labels[publishertarget.WorktreeLabel] != boundary.Placement.Worktree.Label.FullLabel || boundary.Placement.Worktree.Label.FullLabel == "" {
		return errors.New("publisher endpoint volumes belong to another worktree")
	}
	if boundary.StateRoot == "" || !filepath.IsAbs(boundary.StateRoot) {
		return errors.New("compose endpoint rotation requires the private owner state root")
	}
	stateMount, _, err := endpointMount(owner, filepath.Join(boundary.StateRoot, "owner-state"))
	if err != nil || stateMount.Type != "volume" || !stateMount.RW || stateMount.Name == "" {
		return errors.New("compose owner state requires a separate private named volume")
	}
	stateConsumers, err := boundary.runner().Run(ctx, nil, "container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "volume="+stateMount.Name)
	if err != nil {
		return err
	}
	for _, id := range strings.Fields(string(stateConsumers)) {
		if id != owner.ID {
			return errors.New("publisher state volume is mounted by another container")
		}
	}
	volumes := map[string]bool{}
	for _, app := range apps {
		if app.Service == "" || !filepath.IsAbs(app.Path) || filepath.Clean(app.Path) != app.Path {
			return errors.New("app endpoint requires a service and absolute descriptor path")
		}
		current, err := publishertarget.Inspect(ctx, boundary.runner(), app.Container.ID)
		if err != nil {
			return err
		}
		app.Container = current
		mount, relative, err := endpointMount(owner, app.Path)
		if err != nil || mount.Type != "volume" || !mount.RW || mount.Name == "" || volumes[mount.Name] || mount.Name == stateMount.Name {
			return errors.New("each app endpoint requires its own writable named volume")
		}
		volumes[mount.Name] = true
		matched := false
		for _, consumer := range app.Container.Mounts {
			if consumer.Type == "volume" && consumer.Name == stateMount.Name {
				return errors.New("app must not mount publisher state")
			}
			if consumer.Type == "volume" && consumer.Name == mount.Name && !consumer.RW {
				endpoint := filepath.Join(consumer.Destination, relative)
				matched = slices.Contains(app.Container.Config.Env, "TNL_APP_ENDPOINT="+endpoint)
			}
		}
		if !matched || app.Container.Config.Labels[publishertarget.WorktreeLabel] != boundary.Placement.Worktree.Label.FullLabel {
			return errors.New("app must mount only its endpoint volume read-only and select it with TNL_APP_ENDPOINT")
		}
		ids, err := boundary.runner().Run(ctx, nil, "container", "ls", "--all", "--quiet", "--no-trunc", "--filter", "volume="+mount.Name)
		if err != nil {
			return err
		}
		for _, id := range strings.Fields(string(ids)) {
			if id != owner.ID && id != app.Container.ID {
				return errors.New("app endpoint volume is mounted by another container")
			}
		}
	}
	// validate all consumers before changing any descriptor.
	for _, app := range apps {
		endpoint, err := caps.Issue(privateprotocol.CapabilityRequest{Scope: "app", Service: &app.Service})
		if err != nil {
			return err
		}
		endpoint.Url = boundary.URL()
		if err := writeComposeEndpoint(app.Path, endpoint, boundary.URL()); err != nil {
			return err
		}
	}
	return nil
}

func endpointMount(c publishertarget.Container, path string) (publishertarget.Mount, string, error) {
	var selected publishertarget.Mount
	var relative string
	for _, mount := range c.Mounts {
		rel, err := filepath.Rel(mount.Destination, path)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") && len(mount.Destination) > len(selected.Destination) {
			selected, relative = mount, rel
		}
	}
	if selected.Destination == "" {
		return selected, "", errors.New("endpoint is outside a mounted private volume")
	}
	return selected, relative, nil
}

func writeComposeEndpoint(path string, endpoint privateprotocol.Endpoint, authority string) error {
	if endpoint.Scope != "app" || endpoint.Url != authority {
		return privateprotocol.ErrForbidden
	}
	if err := privateprotocol.ValidateComposeAppEndpoint(endpoint, authority); err != nil {
		return err
	}
	// check existing ancestors before MkdirAll, which otherwise follows a
	// symlink and could create a directory outside the endpoint volume.
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return errors.New("compose endpoint ancestors must be directories without symlinks")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if directory == filepath.Dir(directory) {
			break
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	canonical, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || canonical != filepath.Dir(path) {
		return errors.New("compose endpoint directory must not contain symlinks")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := clientstate.ValidatePrivateFile(info, true); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if err := clientstate.ValidatePrivateFile(info, false); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".endpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := json.NewEncoder(file).Encode(endpoint); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
