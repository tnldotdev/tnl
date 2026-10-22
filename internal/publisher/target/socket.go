package target

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Socket implements the discovery subset inside a publisher image without
// requiring a Docker CLI there. host owner queries still use compose exec.
// the path is explicit and only a local unix socket is supported.
type Socket struct{ Path string }

func (s Socket) Run(ctx context.Context, _ []byte, args ...string) ([]byte, error) {
	path := s.Path
	if path == "" {
		path = "/var/run/docker.sock"
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\r\n") {
		return nil, errors.New("docker discovery requires an absolute unix socket path")
	}
	if len(args) == 2 && args[0] == "context" && args[1] == "inspect" {
		return json.Marshal([]any{map[string]any{"Endpoints": map[string]any{"docker": map[string]string{"Host": "unix://" + path}}}})
	}
	endpoint := ""
	list := false
	filters := map[string][]string{}
	switch {
	case len(args) == 4 && args[0] == "container" && args[1] == "inspect" && args[2] == "--" && validIdentifier(args[3]):
		endpoint = "/containers/" + url.PathEscape(args[3]) + "/json"
	case len(args) == 4 && args[0] == "network" && args[1] == "inspect" && args[2] == "--" && validIdentifier(args[3]):
		endpoint = "/networks/" + url.PathEscape(args[3])
	case len(args) >= 3 && args[0] == "container" && args[1] == "ls":
		list = true
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "--quiet", "--no-trunc", "--all":
			case "--filter":
				i++
				if i >= len(args) {
					return nil, errors.New("missing Docker filter")
				}
				key, value, ok := strings.Cut(args[i], "=")
				if !ok || key != "network" && key != "volume" {
					return nil, errors.New("unsupported Docker filter")
				}
				filters[key] = append(filters[key], value)
			default:
				return nil, errors.New("unsupported Docker list option")
			}
		}
	case len(args) == 12 && args[0] == "compose" && args[1] == "--project-directory" && args[3] == "--file" && args[5] == "--project-name" && args[7] == "ps" && args[8] == "--status" && args[9] == "running" && args[10] == "--quiet":
		list = true
		filters["label"] = []string{"com.docker.compose.project=" + args[6], "com.docker.compose.service=" + args[11], "com.docker.compose.oneoff=False"}
		filters["status"] = []string{"running"}
	default:
		return nil, errors.New("unsupported Docker socket operation")
	}
	if list {
		encoded, err := json.Marshal(filters)
		if err != nil {
			return nil, err
		}
		query := url.Values{"all": {"true"}, "filters": {string(encoded)}}
		endpoint = "/containers/json?" + query.Encode()
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", "http://docker/v1.47"+endpoint, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("cannot reach the local Docker socket: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil || len(data) > 8<<20 || response.StatusCode != 200 {
		return nil, errors.New("local Docker discovery failed")
	}
	if list {
		var containers []struct {
			ID string `json:"Id"`
		}
		if json.Unmarshal(data, &containers) != nil {
			return nil, errors.New("invalid Docker container list")
		}
		ids := make([]string, 0, len(containers))
		for _, c := range containers {
			ids = append(ids, c.ID)
		}
		return []byte(strings.Join(ids, "\n")), nil
	}
	// inspect CLI results are arrays; the Engine API returns a single object.
	return append(append([]byte{'['}, data...), ']'), nil
}
