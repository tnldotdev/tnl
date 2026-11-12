// package connectionruntime owns one bounded connector session and its
// private local IPC. public runtime metadata never contains capabilities or keys.
package runtime

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"path/filepath"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

const Schema = 1
const MaxBytes = 128 << 10

type Capabilities struct {
	Schema int `json:"schema"`
	Operations []string `json:"capabilities"`
	EnvironmentVisitors bool `json:"environment_visitors"`
}

var (
	ErrInvalid      = errors.New("connection request is invalid")
	ErrUnauthorized = errors.New("connection handle is not owned by this project or user")
	ErrExpired      = errors.New("connection session expired; prepare it again")
	ErrUnavailable  = errors.New("connector connection is unavailable")
	ErrTransport    = errors.New("connector or verified preflight adapter is not installed")
	ErrTeam         = errors.New("workload requires a configured team selector")
	ErrCleanup      = errors.New("connection owner cleanup failed")
	ErrUnprepared   = errors.New("service is not prepared; await its connection handle first")
)

// Context is nonsecret. the action requests an OIDC assertion for Audience only
// after checking this version and the selected project/policy/service scope.
type Context struct {
	Environment      *EnvironmentSelection `json:"environment,omitempty"`
	Schema           int                   `json:"schema"`
	Directory        string                `json:"directory"`
	ConfigDigest     string                `json:"config_digest"`
	Server           string                `json:"server"`
	Audience         string                `json:"audience"`
	TeamID           string                `json:"team_id"`
	ProjectKey       string                `json:"project_key"`
	SourceID         string                `json:"source_id"`
	WorktreeKey      string                `json:"worktree_key"`
	ProjectLabel     string                `json:"project_label"`
	Services         []string              `json:"services"`
}

// environmentSelection is nonsecret intent. only authority preparation grants
// access, and its returned service IDs stay fixed for this owner's lifetime.
type EnvironmentSelection struct {
	Environment  controlv1.EnvironmentReference `json:"environment"`
	PermissionID string                         `json:"permission_id"`
	Services     map[string]string              `json:"services"`
}

func (s EnvironmentSelection) Validate() error {
	server, err := clientstate.CanonicalServer(s.Environment.Server)
	if err != nil || server != s.Environment.Server || !naming.ValidProjectKey(s.Environment.ProjectKey) || !opaqueid.Valid(s.Environment.EnvironmentId, opaqueid.EnvironmentPrefix) || !opaqueid.Valid(s.PermissionID, "mwp_") || len(s.Services) < 1 || len(s.Services) > 32 {
		return ErrInvalid
	}
	for name, protocol := range s.Services {
		if !naming.ValidServiceName(name) || (protocol != "http" && protocol != "tcp" && protocol != "postgres" && protocol != "mysql" && protocol != "kubernetes") {
			return ErrInvalid
		}
	}
	return nil
}

type EnvironmentStart struct {
	Schema    int                  `json:"schema"`
	Selection EnvironmentSelection `json:"selection"`
	Source authorityv1.IdentitySourceSelection `json:"source"`
	// acquisition and environment are private startup inputs, never observations.
	// absent acquisition selects the shared challenge/reply callback transport.
	Acquisition *workload.Acquisition `json:"acquisition,omitempty"`
	Environment *SDKEnvironment `json:"source_environment,omitempty"`
	GitHubActionsRefresh *GitHubActionsRefresh `json:"github_actions_refresh,omitempty"`
}

func (EnvironmentStart) String() string { return "private environment startup request" }
func (EnvironmentStart) GoString() string { return "private environment startup request" }

// environmentBinding is a projection of the canonical authority response,
// excluding the native-owned session credential and ephemeral signing key.
type EnvironmentBinding struct {
	Environment               controlv1.EnvironmentReference                   `json:"environment"`
	AppliedDefinitionRevision int64                                            `json:"applied_definition_revision"`
	MutationRevision          int64                                            `json:"mutation_revision"`
	Services                  map[string]authorityv1.EnvironmentVisitorService `json:"services"`
}

type StartRequest struct {
	Schema  int     `json:"schema"`
	Context Context `json:"context"`
}

func (StartRequest) String() string   { return "private connection startup request" }
func (StartRequest) GoString() string { return "private connection startup request" }

type GitHubActionsRefresh struct {
	Audience     string `json:"audience"`
	RequestURL   string `json:"request_url"`
	RequestToken string `json:"request_token"`
}

func (GitHubActionsRefresh) String() string   { return "private GitHub Actions refresh source" }
func (GitHubActionsRefresh) GoString() string { return "private GitHub Actions refresh source" }

// Getenv exposes only the explicitly transferred job runtime, never ambient
// process input or a later SDK request's provider credentials.
func (s GitHubActionsRefresh) Getenv(name string) string {
	switch name {
	case "GITHUB_ACTIONS":
		return "true"
	case "ACTIONS_ID_TOKEN_REQUEST_URL":
		return s.RequestURL
	case "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
		return s.RequestToken
	default:
		return ""
	}
}

type Request struct {
	Schema            int                 `json:"schema"`
	Directory         string              `json:"directory"`
	ConfigDigest      string              `json:"config_digest"`
	Service           string              `json:"service,omitempty"`
	Assertion         string              `json:"assertion,omitempty"`
	IdentityReply *authorityv1.IdentitySourceReply `json:"identity_reply,omitempty"`
	AcquireAssertion  bool                `json:"acquire_assertion,omitempty"`
	RequestedAt       string              `json:"requested_at,omitempty"`
	SDKRequestHandle  string              `json:"sdk_request_handle,omitempty"`
	SDKEnvironment    *SDKEnvironment     `json:"sdk_environment,omitempty"`
}

// SDKEnvironment is request-private provider input from the application process.
// owner startup snapshots and registry records must never retain these values.
type SDKEnvironment struct {
	GitHubActions      string `json:"github_actions,omitempty"`
	GitHubRequestURL   string `json:"github_request_url,omitempty"`
	GitHubRequestToken string `json:"github_request_token,omitempty"`
	VercelTokenFile    string `json:"vercel_token_file,omitempty"`
	VercelToken        string `json:"vercel_token,omitempty"`
	TokenEnv           string `json:"token_env,omitempty"`
	TokenValue         string `json:"token_value,omitempty"`
}

func (SDKEnvironment) String() string   { return "private SDK provider environment" }
func (SDKEnvironment) GoString() string { return "private SDK provider environment" }

func (e SDKEnvironment) Getenv(name string) string {
	if name != "" && name == e.TokenEnv {
		return e.TokenValue
	}
	switch name {
	case "GITHUB_ACTIONS":
		return e.GitHubActions
	case "ACTIONS_ID_TOKEN_REQUEST_URL":
		return e.GitHubRequestURL
	case "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
		return e.GitHubRequestToken
	case "VERCEL_OIDC_TOKEN_FILE":
		return e.VercelTokenFile
	case "VERCEL_OIDC_TOKEN":
		return e.VercelToken
	default:
		return ""
	}
}

func (Request) String() string   { return "private connection request" }
func (Request) GoString() string { return "private connection request" }

type TLSOptions struct {
	ServerName         string `json:"servername"`
	RejectUnauthorized bool   `json:"rejectUnauthorized"`
	CA                 string `json:"ca,omitempty"`
}

func (TLSOptions) String() string   { return "private native TLS options" }
func (TLSOptions) GoString() string { return "private native TLS options" }

// Connection is sent only over capability-authenticated IPC. Host is always the
// local dial address; SSL.ServerName and URL retain the approved managed name.
// connector admission never exports an application client certificate or key.
type Connection struct {
	Schema      int         `json:"schema"`
	Protocol    string      `json:"protocol"`
	Host        string      `json:"host"`
	Port        int         `json:"port"`
	SSL         *TLSOptions `json:"ssl,omitempty"`
	URL         string      `json:"url,omitempty"`
	Kubeconfig  string      `json:"kubeconfig,omitempty"`
	Context     string      `json:"context,omitempty"`
	ExpiresAt   time.Time   `json:"expires_at"`
	TransportID string      `json:"transport_id"`
}

func (Connection) String() string   { return "private connector connection" }
func (Connection) GoString() string { return "private connector connection" }

func (c Connection) Validate() error {
	if c.Schema != Schema || !opaqueid.Valid(c.TransportID, "ctg_") {
		return ErrInvalid
	}
	if !c.ExpiresAt.After(time.Now()) {
		return ErrExpired
	}
	return nil
}

// Prepared pairs one owner's public metadata with its current private snapshot.
// readers never re-evaluate project configuration, Git, or authentication.
type Prepared struct {
	Environment    *EnvironmentBinding    `json:"environment,omitempty"`
	Schema         int                    `json:"schema"`
	ProjectRuntime meta.PublicMetadata    `json:"project_runtime"`
	Connection     Connection             `json:"connection"`
	Verification   *AssertionVerification `json:"verification,omitempty"`
}

// SDKPrepared is the private native selection adapter; public start/read outputs
// retain their separate schema-1 shapes.
type SDKPrepared struct {
	Schema   int      `json:"schema"`
	Owner    SDKOwner `json:"owner"`
	Prepared Prepared `json:"prepared"`
}

// SDKOwner is the same capability reference on cold startup and warm selection.
// project metadata belongs to the prepared snapshot, not the owner reference.
type SDKOwner struct {
	ConnectionHandle string    `json:"connection_handle"`
	Executable       string    `json:"executable"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (s Status) SDKOwner() SDKOwner {
	return SDKOwner{ConnectionHandle: s.ConnectionHandle, Executable: s.Executable, ExpiresAt: s.ExpiresAt}
}

// AssertionVerification comes only from authority-confirmed exact assertion
// bytes. it is a nonsecret cache selector, never visitor authorization.
type AssertionVerification struct {
	Digest    string    `json:"digest"`
	Binding   string    `json:"binding"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (Prepared) String() string   { return "private prepared connection" }
func (Prepared) GoString() string { return "private prepared connection" }

func (p Prepared) Validate() error {
	if p.Schema != Schema {
		return ErrInvalid
	}
	return p.Connection.Validate()
}

type Status struct {
	Environment      *EnvironmentBinding `json:"environment,omitempty"`
	Schema           int                 `json:"schema"`
	State            string              `json:"state"`
	PID              int                 `json:"pid"`
	ExpiresAt        time.Time           `json:"expires_at"`
	ProjectRuntime   meta.PublicMetadata `json:"project_runtime"`
	ConnectionHandle string              `json:"connection_handle"`
	Executable       string              `json:"executable"`
	Kubeconfig       string              `json:"kubeconfig,omitempty"`
	Reason           string              `json:"reason,omitempty"`
	CleanupComplete *bool `json:"cleanup_complete,omitempty"`
}

// Backend is implemented by the native CLI's human/workload adapters. Start
// establishes identity and the authorized snapshot; Connect prepares only its
// requested service. Renew returns its current finite authorization deadline.
// snapshots contain metadata and assertion verification from one atomic read.
type Backend interface {
	PreparationBackend
	Start(context.Context) (meta.PublicMetadata, time.Time, error)
	Attach(context.Context, string) error
	ProjectRuntime() meta.PublicMetadata
	Renew(context.Context) (time.Time, error)
	Close(context.Context) error
}

// PreparationBackend prepares a service and reads its owner's coherent snapshot.
// assertion verification belongs to that snapshot, not a separately sampled value.
type PreparationBackend interface {
	UseAssertion(context.Context, string) error
	Connect(context.Context, string) (Connection, error)
	SnapshotFor(string, string) (Prepared, error)
}

// OwnerConfig declares the capabilities composed into this owner. an absent
// operation is intentionally unavailable, not inferred from the backend's type.
type OwnerConfig struct {
	Backend Backend
	// refreshed authority may advance the proof horizon; the backend retains
	// any absolute hard limit. without this source, renewal can only shorten it.
	AuthorizationDeadline func() (time.Time, <-chan struct{})
	// persistent owners follow their application instead of a session deadline.
	// their service snapshots and admissions still retain finite authorization.
	Persistent        bool
	OwnerAlive        func() bool
	Done              <-chan error
	SDKPrepare        func(context.Context, Request) (SDKPrepared, error)
	Kubernetes        KubernetesBackend
	Environment       func() *EnvironmentBinding
	IdentityChallenge func() (authorityv1.IdentitySourceChallenge, error)
	UseIdentityReply func(context.Context, Request) error
	// closed reports the actual joined cleanup result, including failed startup.
	Closed func(error)
}

// KubernetesBackend owns generated kubeconfig files and exec credentials.
type KubernetesBackend interface {
	Kubeconfig() string
	Credential(context.Context, string) (credentialv1.ExecCredential, error)
}

func ReadJSON(reader io.Reader, destination any) error {
	data, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil || len(data) > MaxBytes {
		return ErrInvalid
	}
	if jsonv2.Unmarshal(data, destination, jsonv2.RejectUnknownMembers(true)) != nil {
		return ErrInvalid
	}
	return nil
}

func (c Context) Validate() error {
	if c.Environment != nil {
		if c.Environment.Validate() != nil || c.Schema != Schema || !filepath.IsAbs(c.Directory) || len(c.Directory) > 4096 || len(c.ConfigDigest) != 64 || c.Server != c.Environment.Environment.Server || c.Audience != c.Server || c.ProjectKey != c.Environment.Environment.ProjectKey || c.TeamID != "" || c.SourceID != "" || len(c.Services) != len(c.Environment.Services) {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, name := range c.Services {
			if _, ok := c.Environment.Services[name]; !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
		}
		return nil
	}
	if c.Schema != Schema || !filepath.IsAbs(c.Directory) || len(c.Directory) > 4096 || len(c.ConfigDigest) != 64 ||
		c.Server == "" || c.Audience != c.Server || c.ProjectKey == "" || c.SourceID == "" || c.WorktreeKey == "" ||
		len(c.Services) == 0 || len(c.Services) > 32 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, name := range c.Services {
		if !naming.ValidServiceName(name) || seen[name] {
			return ErrInvalid
		}
		seen[name] = true
	}
	return nil
}
