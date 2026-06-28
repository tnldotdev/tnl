package serviceapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/credentials"
)

const minimumServiceSecretBytes = 32

// BearerSecrets authenticates a current service secret and an optional previous
// secret retained only for a rolling rotation.
type BearerSecrets struct {
	current     [sha256.Size]byte
	previous    [sha256.Size]byte
	hasPrevious bool
	valid       bool
}

func NewBearerSecrets(current, previous string) (BearerSecrets, error) {
	if !validServiceSecret(current) || previous != "" && (!validServiceSecret(previous) || previous == current) {
		return BearerSecrets{}, errors.New("serviceapi: service secrets are invalid")
	}
	result := BearerSecrets{current: sha256.Sum256([]byte(current)), valid: true}
	if previous != "" {
		result.previous = sha256.Sum256([]byte(previous))
		result.hasPrevious = true
	}
	return result, nil
}

func (s BearerSecrets) Authenticate(header http.Header) bool {
	if !s.valid {
		return false
	}
	token, err := credentials.Bearer(header)
	if err != nil {
		return false
	}
	return s.Matches(token)
}

func (s BearerSecrets) Matches(candidate string) bool {
	if !s.valid {
		return false
	}
	digest := sha256.Sum256([]byte(candidate))
	current := subtle.ConstantTimeCompare(digest[:], s.current[:])
	previous := 0
	if s.hasPrevious {
		previous = subtle.ConstantTimeCompare(digest[:], s.previous[:])
	}
	return current|previous == 1
}

func (s BearerSecrets) Valid() bool { return s.valid }

func validServiceSecret(value string) bool {
	return len(value) >= minimumServiceSecretBytes && len(value) <= 4096 &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, " \t\r\n,")
}
