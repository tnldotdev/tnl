// package privateprotocol owns the bounded, machine-local SDK protocol.
package privateprotocol

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/tnldotdev/tnl/internal/projectmeta"
)

const Version = 1
const MaxBytes = 64 << 10

type Prepare struct {
	Version   int    `json:"version"`
	Directory string `json:"directory"`
	Service   string `json:"service,omitempty"`
	Framework string `json:"framework"`
	Owner     string `json:"owner"`
	PID       int    `json:"pid"`
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
