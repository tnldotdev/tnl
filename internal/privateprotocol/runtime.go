// package privateprotocol owns the bounded, machine-local SDK protocol.
package privateprotocol

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/tnldotdev/tnl/internal/projectmeta"
)

const Version = 1
const MaxBytes = 64 << 10

var ownerPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func ValidOwner(owner string) bool { return ownerPattern.MatchString(owner) }

type Framework string

const (
	FrameworkNode Framework = "node"
	FrameworkBun  Framework = "bun"
	FrameworkVite Framework = "vite"
	FrameworkNext Framework = "next"
	FrameworkPython Framework = "python"
)

func (framework Framework) Valid() bool {
	switch framework {
	case FrameworkNode, FrameworkBun, FrameworkVite, FrameworkNext, FrameworkPython:
		return true
	default:
		return false
	}
}

type Prepare struct {
	Version   int       `json:"version"`
	Directory string    `json:"directory"`
	Service   string    `json:"service,omitempty"`
	Framework Framework `json:"framework"`
	Owner     string    `json:"owner"`
	PID       int       `json:"pid"`
}

type Assignment struct {
	Version        int                        `json:"version"`
	RegistrationID string                     `json:"registration_id"`
	Service        string                     `json:"service"`
	Hostname       string                     `json:"hostname"`
	PublicURL      string                     `json:"public_url"`
	Project        projectmeta.PublicMetadata `json:"project"`
}

type Registration struct {
	Version        int    `json:"version"`
	RegistrationID string `json:"registration_id"`
	Owner          string `json:"owner"`
	Target         string `json:"target,omitempty"`
}

// AdHocRegister binds one invocation to an already-listening local target.
// the credential is sent only across the private socket and never enters status.
type AdHocRegister struct {
	Version        int          `json:"version"`
	RegistrationID string       `json:"registration_id"`
	Owner          string       `json:"owner"`
	PID            int          `json:"pid"`
	Target         string       `json:"target"`
	ServerURL      string       `json:"server_url,omitempty"`
	Credential     string       `json:"credential"`
	AllowIP        []string     `json:"allow_ip,omitempty"`
	AllowAllIPs    bool         `json:"allow_all_ips,omitempty"`
	Limits         *AdHocLimits `json:"limits,omitempty"`
}

type AdHocLimits struct {
	Requests    int             `json:"requests,omitempty"`
	Rate        *AdHocRateLimit `json:"rate,omitempty"`
	Concurrency int             `json:"concurrency,omitempty"`
}

type AdHocRateLimit struct {
	Requests int    `json:"requests"`
	Per      string `json:"per"`
}

type AdHocState string

const (
	AdHocStarting   AdHocState = "starting"
	AdHocPublishing AdHocState = "publishing"
	AdHocRoutable   AdHocState = "routable"
	AdHocDraining   AdHocState = "draining"
	AdHocStopped    AdHocState = "stopped"
	AdHocFailed     AdHocState = "failed"
)

func (state AdHocState) Valid() bool {
	switch state {
	case AdHocStarting, AdHocPublishing, AdHocRoutable, AdHocDraining, AdHocStopped, AdHocFailed:
		return true
	default:
		return false
	}
}

// AdHocStatus never contains credentials, visitor requests, or browser metadata.
type AdHocStatus struct {
	Version          int        `json:"version"`
	RegistrationID   string     `json:"registration_id"`
	State            AdHocState `json:"state"`
	PublicURLID      string     `json:"public_url_id,omitempty"`
	PublicURL        string     `json:"public_url,omitempty"`
	PublishRunNumber uint64     `json:"publish_run_number,omitempty"`
	FailureCode      string     `json:"failure_code,omitempty"`
}

type Problem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func Decode(w http.ResponseWriter, r *http.Request, value any) error {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Origin") != "" {
		return errors.New("invalid private request")
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing private request data")
	}
	return nil
}

func Write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
