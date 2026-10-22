package protocol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	api "github.com/tnldotdev/tnl/pkg/api/publisher/local/v1"
)

type Endpoint = api.Endpoint
type CapabilityRequest = api.CapabilityRequest
type Lease = api.Lease
type Invocation = api.Invocation
type Check = api.Check

var ErrUnauthorized = errors.New("local publisher capability is invalid")
var ErrForbidden = errors.New("local publisher capability does not permit this operation")

func Random(bytes int) (string, error) {
	value := make([]byte, bytes)
	_, err := rand.Read(value)
	return hex.EncodeToString(value), err
}

// ValidateEndpoint accepts only an exact numeric loopback HTTP origin. no DNS,
// proxy, userinfo, path, query, or fragment participates in local authentication.
func ValidateEndpoint(e Endpoint) error {
	u, err := url.Parse(e.Url)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return ErrUnauthorized
	}
	address, err := netip.ParseAddrPort(u.Host)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 || address.String() != u.Host {
		return ErrUnauthorized
	}
	if e.Version != 1 || !e.Scope.Valid() || !ValidOwner(e.OwnerId) || len(e.Capability) != 64 {
		return ErrUnauthorized
	}
	if value, err := hex.DecodeString(e.Capability); err != nil || len(value) != 32 {
		return ErrUnauthorized
	}
	if e.Scope == "app" && (e.Service == nil || !naming.ValidServiceName(*e.Service) || e.InvocationId != nil) ||
		e.Scope == "invocation" && (e.InvocationId == nil || !opaqueid.Valid(*e.InvocationId, opaqueid.InvocationPrefix) || e.Service != nil) ||
		e.Scope == "owner" && (e.Service != nil || e.InvocationId != nil) {
		return ErrUnauthorized
	}
	return nil
}

// RuntimeDir is private state, not a shared /tmp discovery location.
func RuntimeDir(root string) (string, error) {
	root, err := clientstate.PrepareRoot(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "runtime")
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	return path, clientstate.ValidatePrivateFile(info, true)
}

func DescriptorPath(root, project string) (string, error) {
	directory, err := RuntimeDir(root)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(project))
	return filepath.Join(directory, "owner-"+hex.EncodeToString(digest[:12])+".json"), nil
}

func ReadEndpoint(path string) (Endpoint, error) {
	return readEndpoint(path, ValidateEndpoint)
}

func readEndpoint(path string, validate func(Endpoint) error) (Endpoint, error) {
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return Endpoint{}, err
	}
	if err := clientstate.ValidatePrivateFile(info, true); err != nil {
		return Endpoint{}, err
	}
	file, err := clientstate.OpenPrivateFile(path)
	if err != nil {
		return Endpoint{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Endpoint{}, err
	}
	if opened.Size() > MaxBytes {
		return Endpoint{}, errors.New("local publisher descriptor exceeds size limit")
	}
	var endpoint Endpoint
	decoder := json.NewDecoder(io.LimitReader(file, MaxBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&endpoint); err != nil {
		return Endpoint{}, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Endpoint{}, ErrUnauthorized
	}
	return endpoint, validate(endpoint)
}

// WriteEndpoint replaces a descriptor atomically within its verified private
// directory. shutdown removes it only if it still names this owner instance.
func WriteEndpoint(path string, endpoint Endpoint) error {
	if err := ValidateEndpoint(endpoint); err != nil {
		return err
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
	if err := json.NewEncoder(file).Encode(endpoint); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func RemoveEndpoint(path, ownerID string) {
	if current, err := ReadEndpoint(path); err == nil && current.OwnerId == ownerID {
		_ = os.Remove(path)
	}
}

type grantKey struct{}

// capabilityGrant owns only scalar values; API descriptors are fresh views.
type capabilityGrant struct {
	url, ownerID, capability string
	scope                    api.EndpointScope
	service, invocationID    string
}

func (g capabilityGrant) endpoint() Endpoint {
	e := Endpoint{Version: 1, Url: g.url, OwnerId: g.ownerID, Capability: g.capability, Scope: g.scope}
	if g.scope == "app" {
		e.Service = &g.service
	}
	if g.scope == "invocation" {
		e.InvocationId = &g.invocationID
	}
	return e
}

type Capabilities struct {
	mu     sync.Mutex
	owner  capabilityGrant
	grants map[[32]byte]capabilityGrant
}

func NewCapabilities(address string) (*Capabilities, error) {
	secret, err := Random(32)
	if err != nil {
		return nil, err
	}
	id, err := Random(16)
	if err != nil {
		return nil, err
	}
	e := Endpoint{Version: 1, Url: address, OwnerId: id, Capability: secret, Scope: "owner"}
	if err := ValidateEndpoint(e); err != nil {
		return nil, err
	}
	owner := capabilityGrant{url: address, ownerID: id, capability: secret, scope: "owner"}
	return &Capabilities{owner: owner, grants: map[[32]byte]capabilityGrant{sha256.Sum256([]byte(secret)): owner}}, nil
}

func (c *Capabilities) Owner() Endpoint { return c.owner.endpoint() }

func (c *Capabilities) Issue(request CapabilityRequest) (Endpoint, error) {
	secret, err := Random(32)
	if err != nil {
		return Endpoint{}, err
	}
	e := c.owner.endpoint()
	e.Scope, e.Service, e.InvocationId, e.Capability = api.EndpointScope(request.Scope), request.Service, request.InvocationId, secret
	if !request.Scope.Valid() || ValidateEndpoint(e) != nil {
		return Endpoint{}, ErrForbidden
	}
	grant := capabilityGrant{url: e.Url, ownerID: e.OwnerId, capability: e.Capability, scope: e.Scope, service: optional(e.Service), invocationID: optional(e.InvocationId)}
	c.mu.Lock()
	defer c.mu.Unlock()
	// bounded grants are stable per selected service/invocation, so SDK retries
	// cannot exhaust owner memory or revoke another application's capability.
	for _, existing := range c.grants {
		if existing.scope == grant.scope && existing.service == grant.service && existing.invocationID == grant.invocationID {
			return existing.endpoint(), nil
		}
	}
	if len(c.grants) >= 256 {
		return Endpoint{}, ErrForbidden
	}
	c.grants[sha256.Sum256([]byte(secret))] = grant
	return grant.endpoint(), nil
}

func optional(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func Grant(r *http.Request) Endpoint {
	value, found := r.Context().Value(grantKey{}).(capabilityGrant)
	if !found {
		return Endpoint{}
	}
	return value.endpoint()
}

func (c *Capabilities) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		u, _ := url.Parse(c.owner.url)
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		remote, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || !remote.IsLoopback() || r.Host != u.Host || len(r.Header.Values("Origin")) != 0 || r.URL.IsAbs() || len(r.Header.Values("Authorization")) != 1 {
			Write(w, 401, Problem{Code: "runtime.unauthorized", Message: "use the current private endpoint descriptor"})
			return
		}
		bearer := r.Header.Get("Authorization")
		if !strings.HasPrefix(bearer, "Bearer ") || len(bearer) != 71 {
			Write(w, 401, Problem{Code: "runtime.unauthorized", Message: "use the current private endpoint descriptor"})
			return
		}
		c.mu.Lock()
		grant, found := c.grants[sha256.Sum256([]byte(bearer[7:]))]
		c.mu.Unlock()
		if !found {
			Write(w, 401, Problem{Code: "runtime.unauthorized", Message: "use the current private endpoint descriptor"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBytes)
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, grantKey{}, grant)))
	})
}

// Call never uses environment proxies or follows redirects carrying a capability.
func Call(ctx context.Context, e Endpoint, method, path string, input, output any) error {
	if err := ValidateEndpoint(e); err != nil {
		return err
	}
	return callEndpoint(ctx, e, method, path, input, output)
}

func callEndpoint(ctx context.Context, e Endpoint, method, path string, input, output any) error {
	if !strings.HasPrefix(path, "/v1/") || strings.ContainsAny(path, "\r\n") {
		return ErrForbidden
	}
	var body bytes.Buffer
	if input != nil {
		if err := json.NewEncoder(&body).Encode(input); err != nil {
			return err
		}
	}
	if body.Len() > MaxBytes {
		return errors.New("local publisher request exceeds size limit")
	}
	request, err := http.NewRequestWithContext(ctx, method, e.Url+path, &body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+e.Capability)
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	timeout := 30 * time.Second
	if path == "/v1/unregister" {
		timeout = 75 * time.Second
	}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	observability.InjectLocalTrace(ctx, request.Header)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == 401 {
		return ErrUnauthorized
	}
	if response.StatusCode == 403 {
		return ErrForbidden
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var problem Problem
		_ = json.NewDecoder(io.LimitReader(response.Body, MaxBytes)).Decode(&problem)
		return &ResponseError{Status: response.StatusCode, Code: problem.Code}
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(output)
	}
	return nil
}

type ResponseError struct {
	Status int
	Code   string
}

func (e *ResponseError) Error() string { return "local publisher request failed (" + e.Code + ")" }
