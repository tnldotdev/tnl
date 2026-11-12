// package privateprotocol owns the bounded, machine-local SDK protocol.
package protocol

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	api "github.com/tnldotdev/tnl/pkg/api/publisher/local/v1"
)

const Version = 1
const MaxBytes = 64 << 10

var ownerPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

var ErrApplicationAuthInvalid = errors.New("application publication authentication is invalid")
var ErrApplicationDenied = errors.New("application publication is outside the current grant")
var ErrApplicationUnavailable = errors.New("application publication authority is unavailable")
var ErrApplicationChallengeStale = errors.New("application identity source challenge is stale")

func ValidOwner(owner string) bool { return ownerPattern.MatchString(owner) }

type Framework = api.PrepareFramework

const (
	FrameworkNode   Framework = "node"
	FrameworkBun    Framework = "bun"
	FrameworkVite   Framework = "vite"
	FrameworkNext   Framework = "next"
	FrameworkPython Framework = "python"
)

type Prepare = api.Prepare

type Assignment struct {
	Version        int                 `json:"version"`
	RegistrationID string              `json:"registration_id"`
	Service        string              `json:"service"`
	Hostname       string              `json:"hostname"`
	PublicURL      string              `json:"public_url"`
	Project        meta.PublicMetadata `json:"project"`
}

type Registration = api.Registration
type ApplicationPublication = api.ApplicationPublication
type ApplicationPublicationAccessMode = api.ApplicationPublicationAccessMode

// AcceptedPublication embeds the sole wire shape. Reused is a native-only
// acknowledgment fact: losing a renewal reply must not stop an accepted worker.
type AcceptedPublication struct {
	api.AcceptedPublication
	Reused bool `json:"-"`
}

type Problem = api.Problem

func Decode(w http.ResponseWriter, r *http.Request, value any) error {
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || len(r.Header.Values("Origin")) != 0 {
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

func Write(w http.ResponseWriter, status int, value any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(value)
}
