// package privateprotocol owns the bounded, machine-local SDK protocol.
package privateprotocol

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"

	"github.com/tnldotdev/tnl/internal/projectmeta"
	api "github.com/tnldotdev/tnl/pkg/api/localpublisherv1"
)

const Version = 1
const MaxBytes = 64 << 10

var ownerPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

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
	Version        int                        `json:"version"`
	RegistrationID string                     `json:"registration_id"`
	Service        string                     `json:"service"`
	Hostname       string                     `json:"hostname"`
	PublicURL      string                     `json:"public_url"`
	Project        projectmeta.PublicMetadata `json:"project"`
}

type Registration = api.Registration

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

func Write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
