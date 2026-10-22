// package connectionruntime owns one bounded native connection session and its
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
	"github.com/tnldotdev/tnl/internal/naming"
)

const Schema = 1
const MaxBytes = 128 << 10

var (
	ErrInvalid      = errors.New("connection request is invalid")
	ErrUnauthorized = errors.New("connection handle is not owned by this project or user")
	ErrExpired      = errors.New("connection session expired; prepare it again")
	ErrUnavailable  = errors.New("native connection is unavailable")
	ErrTransport    = errors.New("native connector or verified preflight adapter is not installed")
	ErrTeam         = errors.New("workload requires a configured team selector")
	ErrCleanup      = errors.New("connection owner cleanup failed")
	ErrUnprepared   = errors.New("service is not prepared; await its connection handle first")
)

// Context is nonsecret. the action requests an OIDC assertion for Audience only
// after checking this version and the selected project/policy/service scope.
type Context struct {
	Schema       int      `json:"schema"`
	Directory    string   `json:"directory"`
	ConfigDigest string   `json:"config_digest"`
	Server       string   `json:"server"`
	Audience     string   `json:"audience"`
	TeamID       string   `json:"team_id"`
	ProjectKey   string   `json:"project_key"`
	SourceID     string   `json:"source_id"`
	WorktreeKey  string   `json:"worktree_key"`
	ProjectLabel string   `json:"project_label"`
	Workload     string   `json:"workload,omitempty"`
	Services     []string `json:"services"`
}

type StartRequest struct {
	Schema  int     `json:"schema"`
	Context Context `json:"context"`
	// Assertion is accepted on stdin/private IPC only. never persist this request.
	Assertion string `json:"assertion,omitempty"`
}

func (StartRequest) String() string   { return "private connection startup request" }
func (StartRequest) GoString() string { return "private connection startup request" }

type Request struct {
	Schema           int    `json:"schema"`
	Directory        string `json:"directory"`
	ConfigDigest     string `json:"config_digest"`
	Service          string `json:"service,omitempty"`
	Assertion        string `json:"assertion,omitempty"`
	AcquireAssertion bool   `json:"acquire_assertion,omitempty"`
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
	TransportID string      `json:"transport_id,omitempty"`
}

func (Connection) String() string   { return "private native connection" }
func (Connection) GoString() string { return "private native connection" }

// Prepared pairs one owner's public metadata with its current private snapshot.
// readers never re-evaluate project configuration, Git, or authentication.
type Prepared struct {
	Schema         int                    `json:"schema"`
	ProjectRuntime meta.PublicMetadata    `json:"project_runtime"`
	Connection     Connection             `json:"connection"`
	Verification   *AssertionVerification `json:"verification,omitempty"`
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

type Status struct {
	Schema           int                 `json:"schema"`
	State            string              `json:"state"`
	PID              int                 `json:"pid"`
	ExpiresAt        time.Time           `json:"expires_at"`
	ProjectRuntime   meta.PublicMetadata `json:"project_runtime"`
	ConnectionHandle string              `json:"connection_handle"`
	Executable       string              `json:"executable"`
	Kubeconfig       string              `json:"kubeconfig,omitempty"`
	Reason           string              `json:"reason,omitempty"`
}

// Backend is implemented by the native CLI's human/workload adapters. Start
// establishes identity and the authorized snapshot; Connect prepares only its
// requested service. Renew may narrow a workload's fixed session deadline.
type Backend interface {
	Start(context.Context) (meta.PublicMetadata, time.Time, error)
	Connect(context.Context, string) (Connection, error)
	Prepared(string) (Connection, error)
	Renew(context.Context) (time.Time, error)
	Close(context.Context) error
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
