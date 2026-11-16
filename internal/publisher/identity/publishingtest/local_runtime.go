package publishingtest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// LocalProject pins the management requests accepted by an opted-in fixture.
// declarations are expectations supplied before any worker starts, not responses
// manufactured by the worker's configuration callback.
type LocalProject struct {
	Key, Fingerprint, Worktree, Label, PreviewKey string
	Services                                      map[string]controlv1.ProjectServiceConfiguration
}

type localRuntime struct {
	expected LocalProject
	services map[string]controlv1.Service
	preview  controlv1.Preview
}

func (f *Fixture) ConfigureLocal(project LocalProject) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.local != nil || project.Key == "" || project.Fingerprint == "" || project.Worktree == "" || project.PreviewKey == "" || len(project.Services) == 0 {
		return fmt.Errorf("local fixture requires one exact project and declarations")
	}
	f.local = &localRuntime{expected: project, services: map[string]controlv1.Service{}}
	return nil
}

func (f *Fixture) serveLocal(w http.ResponseWriter, r *http.Request) bool {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	local := len(parts) == 5 && parts[0] == "v1" && parts[1] == "projects" && parts[3] == "local-services"
	preview := r.URL.Path == "/v1/previews" || len(parts) >= 3 && parts[0] == "v1" && parts[1] == "previews"
	discovery := r.Method == http.MethodGet && r.URL.Path == "/v1/discovery"
	if !local && !preview && !discovery {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.local == nil {
		return false
	}
	if discovery {
		facts, err := f.seed.Discovery(r.Context())
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(http.StatusBadGateway)
			return true
		}
		// the backend advertises oidc; configured clients also require its
		// issuer and login flow even when using the explicit owner credential.
		facts.Authentication.Oidc = &controlv1.OIDCAuthenticationFacts{Issuer: f.URL, LoginFlow: controlv1.DeviceCode}
		write(w, facts)
		return true
	}
	if r.Header.Get("Authorization") != "Bearer "+f.OwnerToken {
		denied(w)
		return true
	}
	pinned := f.local.expected
	if local {
		declaration, found := pinned.Services[parts[4]]
		if parts[2] != pinned.Key || !found {
			http.NotFound(w, r)
			return true
		}
		switch r.Method {
		case http.MethodPut:
			var body controlv1.RealizeLocalProjectServiceRequest
			want := controlv1.RealizeLocalProjectServiceRequest{TeamId: "tm_0000000000000000000001",
				SourceFingerprint: pinned.Fingerprint, WorktreeKey: pinned.Worktree, Configuration: declaration}
			if pinned.Label != "" {
				want.WorktreeLabel = &pinned.Label
			}
			if !decode(r, &body) || !reflect.DeepEqual(body, want) {
				w.WriteHeader(http.StatusBadRequest)
				return true
			}
			if _, exists := f.local.services[parts[4]]; !exists {
				saved, err := f.SavedService(r.Context(), parts[4], declaration)
				if err != nil {
					f.t.Error(err)
					w.WriteHeader(http.StatusBadGateway)
					return true
				}
				f.local.services[parts[4]] = saved
			}
		case http.MethodGet:
			query := r.URL.Query()
			if len(query) != 3 || query.Get("team_id") != "tm_0000000000000000000001" ||
				query.Get("source_fingerprint") != pinned.Fingerprint || query.Get("worktree_key") != pinned.Worktree {
				w.WriteHeader(http.StatusBadRequest)
				return true
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return true
		}
		saved, found := f.local.services[parts[4]]
		if !found {
			writeStatus(w, http.StatusNotFound, controlv1.Problem{Code: controlv1.NotFound, Status: 404})
			return true
		}
		saved, _, found = f.backend.Service(saved.Id)
		if !found || !saved.Enabled || saved.TeamId != "tm_0000000000000000000001" {
			writeStatus(w, http.StatusNotFound, controlv1.Problem{Code: controlv1.NotFound, Status: 404})
			return true
		}
		metadata := controlv1.ServiceMetadata{Endpoint: saved.Endpoint, Protocol: saved.Protocol,
			PublisherPool: saved.PublisherPool, TrustRevision: saved.TrustRevision, TargetTls: saved.TargetTls}
		selected := controlv1.LocalProjectService{Service: parts[4], ServiceId: saved.Id, WorktreeKey: pinned.Worktree, Metadata: &metadata}
		if saved.Endpoint != nil {
			selected.Hostname = &saved.Endpoint.Hostname
		}
		write(w, selected)
		return true
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/previews" {
		var body controlv1.CreatePreviewRequest
		if !decode(r, &body) || body.TeamId != "tm_0000000000000000000001" || r.Header.Get("Idempotency-Key") != pinned.PreviewKey {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		if f.local.preview.Id == "" {
			f.local.preview = controlv1.Preview{Id: id(f.t, opaqueid.PreviewPrefix), TeamId: body.TeamId,
				SchemaVersion: 1, CreatedAt: time.Now().UTC(), ServiceIds: []string{}}
		}
		writeStatus(w, http.StatusCreated, f.local.preview)
		return true
	}
	if len(parts) == 4 && parts[2] == f.local.preview.Id && parts[3] == "services" && r.Method == http.MethodPost {
		var body controlv1.AddPreviewServiceRequest
		if !decode(r, &body) || !f.localService(body.ServiceId) {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		if !slices.Contains(f.local.preview.ServiceIds, body.ServiceId) {
			f.local.preview.ServiceIds = append(f.local.preview.ServiceIds, body.ServiceId)
		}
		write(w, f.local.preview)
		return true
	}
	http.NotFound(w, r)
	return true
}

func (f *Fixture) localService(id string) bool {
	for _, service := range f.local.services {
		if service.Id == id {
			current, _, found := f.backend.Service(id)
			return found && current.Enabled && current.TeamId == "tm_0000000000000000000001"
		}
	}
	return false
}

// LocalService reads the actual realization without creating or authorizing it.
func (f *Fixture) LocalService(_ context.Context, name string) (controlv1.Service, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.local == nil {
		return controlv1.Service{}, false
	}
	saved, found := f.local.services[name]
	return saved, found
}

// Transport keeps ordinary HTTP transport semantics for local target probes.
// public service dials use the same authenticated relay streams as Visit; TLS,
// visitor permission, admission and owner-proof consumption remain real.
func (f *Fixture) Transport() (*http.Transport, error) {
	transport := f.HTTP.Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.RootCAs = transport.TLSClientConfig.RootCAs.Clone()
	pem, err := os.ReadFile(f.backend.CAFile)
	if err != nil {
		return nil, err
	}
	if !transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("publishing fixture CA is invalid")
	}
	dial := (&net.Dialer{}).DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port != "443" || !strings.HasSuffix(host, "."+f.Namespace) {
			return dial(ctx, network, address)
		}
		f.mu.Lock()
		var service string
		for runID := range f.seenRuns {
			run, found := f.backend.Run(runID)
			if found && run.Service.Endpoint != nil && run.Service.Endpoint.Hostname == host {
				service = run.Service.Id
				break
			}
		}
		f.mu.Unlock()
		if service == "" {
			return nil, fmt.Errorf("no published fixture service for %s", host)
		}
		return f.backend.OpenHTTPVisitor(ctx, service, netip.MustParseAddrPort("127.0.0.1:45123"), netip.MustParseAddrPort("127.0.0.1:443"))
	}
	return transport, nil
}
