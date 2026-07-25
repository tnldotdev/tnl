package credentials

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	accessPrefix    = "tnl_access_"
	bootstrapPrefix = "tnl_bootstrap_"
	routePrefix     = "tnl_route_"
	leasePrefix     = "tnl_lease_"
	workerPrefix    = "tnl_worker_"
	workloadPrefix  = "tnl_workload_"
	lookupBytes     = 16
	secretBytes     = 32
)

var (
	// ErrInvalidAccessToken is returned for malformed or rejected access tokens.
	ErrInvalidAccessToken = errors.New("invalid access token")
	// ErrInvalidBootstrapToken is returned for malformed bootstrap tokens.
	ErrInvalidBootstrapToken = errors.New("invalid bootstrap token")
	// ErrInvalidRouteToken is returned for malformed or rejected route tokens.
	ErrInvalidRouteToken = errors.New("invalid route token")
	// ErrInvalidLeaseToken is returned for malformed or rejected lease tokens.
	ErrInvalidLeaseToken = errors.New("invalid lease token")
	// ErrInvalidWorkerToken is returned for malformed or rejected worker tokens.
	ErrInvalidWorkerToken = errors.New("invalid worker token")
	// ErrInvalidWorkloadToken is returned for malformed workload tokens.
	ErrInvalidWorkloadToken = errors.New("invalid workload token")
)

// AccessToken authenticates a local principal to the standalone core API.
type AccessToken string

// BootstrapToken authenticates only to the standalone token exchange.
type BootstrapToken string

// RouteToken authorizes lease acquisition for one route.
type RouteToken string

// LeaseToken authorizes operations on one lease generation.
type LeaseToken string

// WorkerToken authenticates one worker session to an edge.
type WorkerToken string

// WorkloadToken authenticates one service-to-service request.
type WorkloadToken string

// CredentialID is the nonsecret lookup portion of a credential.
type CredentialID string

// SecretHash is the stored digest of a random token secret.
type SecretHash [sha256.Size]byte

// BootstrapVerifier is the verification material for one bootstrap token.
type BootstrapVerifier struct {
	id   CredentialID
	hash SecretHash
}

// WorkerVerifier is the nonsecret verification material for one worker token.
type WorkerVerifier struct {
	id   CredentialID
	hash SecretHash
}

// WorkloadVerifier is the nonsecret verification material for one workload token.
type WorkloadVerifier struct {
	id   CredentialID
	hash SecretHash
}

// NewAccessToken creates an access token and its storage values.
func NewAccessToken() (AccessToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(accessPrefix)
	return AccessToken(token), lookupID, hash, err
}

// ParseAccessToken validates an access token and returns its storage lookup values.
func ParseAccessToken(token AccessToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), accessPrefix, ErrInvalidAccessToken)
}

// NewBootstrapToken creates a deployment bootstrap token.
func NewBootstrapToken() (BootstrapToken, error) {
	token, _, _, err := newToken(bootstrapPrefix)
	return BootstrapToken(token), err
}

// ParseBootstrapToken validates a bootstrap token and returns its verifier.
func ParseBootstrapToken(token BootstrapToken) (BootstrapVerifier, error) {
	lookupID, hash, err := parseToken(string(token), bootstrapPrefix, ErrInvalidBootstrapToken)
	return BootstrapVerifier{id: lookupID, hash: hash}, err
}

// NewRouteToken creates a route token and its storage values.
func NewRouteToken() (RouteToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(routePrefix)
	return RouteToken(token), lookupID, hash, err
}

// ParseRouteToken validates a route token and returns its storage lookup values.
func ParseRouteToken(token RouteToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), routePrefix, ErrInvalidRouteToken)
}

// NewLeaseToken creates a lease token and its storage values.
func NewLeaseToken() (LeaseToken, CredentialID, SecretHash, error) {
	token, lookupID, hash, err := newToken(leasePrefix)
	return LeaseToken(token), lookupID, hash, err
}

// ParseLeaseToken validates a lease token and returns its storage lookup values.
func ParseLeaseToken(token LeaseToken) (CredentialID, SecretHash, error) {
	return parseToken(string(token), leasePrefix, ErrInvalidLeaseToken)
}

// NewWorkerToken creates a worker token and its verifier.
func NewWorkerToken() (WorkerToken, WorkerVerifier, error) {
	token, lookupID, hash, err := newToken(workerPrefix)
	return WorkerToken(token), WorkerVerifier{id: lookupID, hash: hash}, err
}

// ParseWorkerToken validates a worker token and returns its verifier.
func ParseWorkerToken(token WorkerToken) (WorkerVerifier, error) {
	lookupID, hash, err := parseToken(string(token), workerPrefix, ErrInvalidWorkerToken)
	return WorkerVerifier{id: lookupID, hash: hash}, err
}

// NewWorkloadToken creates a service-to-service credential.
func NewWorkloadToken() (WorkloadToken, WorkloadVerifier, error) {
	token, lookupID, hash, err := newToken(workloadPrefix)
	return WorkloadToken(token), WorkloadVerifier{id: lookupID, hash: hash}, err
}

// ParseWorkloadToken validates a workload token and returns its verifier.
func ParseWorkloadToken(token WorkloadToken) (WorkloadVerifier, error) {
	lookupID, hash, err := parseToken(string(token), workloadPrefix, ErrInvalidWorkloadToken)
	return WorkloadVerifier{id: lookupID, hash: hash}, err
}

// Matches reports whether token matches this verifier.
func (v BootstrapVerifier) Matches(token BootstrapToken) bool {
	candidate, err := ParseBootstrapToken(token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(v.id), []byte(candidate.id)) == 1 &&
		SecretHashMatches(v.hash[:], candidate.hash)
}

// Matches reports whether token matches this verifier.
func (v WorkerVerifier) Matches(token WorkerToken) bool {
	candidate, err := ParseWorkerToken(token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(v.id), []byte(candidate.id)) == 1 &&
		SecretHashMatches(v.hash[:], candidate.hash)
}

// Matches reports whether token matches this verifier.
func (v WorkloadVerifier) Matches(token WorkloadToken) bool {
	candidate, err := ParseWorkloadToken(token)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(v.id), []byte(candidate.id)) == 1 &&
		SecretHashMatches(v.hash[:], candidate.hash)
}

// String returns the serialized access token.
func (t AccessToken) String() string { return string(t) }

// String returns the serialized bootstrap token.
func (t BootstrapToken) String() string { return string(t) }

// String returns the serialized route token.
func (t RouteToken) String() string { return string(t) }

// String returns the serialized lease token.
func (t LeaseToken) String() string { return string(t) }

// String returns the serialized worker token.
func (t WorkerToken) String() string { return string(t) }

// String returns the serialized workload token.
func (t WorkloadToken) String() string { return string(t) }

// String returns the nonsecret credential ID.
func (id CredentialID) String() string { return string(id) }

func newToken(prefix string) (token string, lookupID CredentialID, hash SecretHash, err error) {
	material := make([]byte, lookupBytes+secretBytes)
	if _, err := rand.Read(material); err != nil {
		return "", "", SecretHash{}, fmt.Errorf("generate credential: %w", err)
	}
	lookupID = CredentialID(base64.RawURLEncoding.EncodeToString(material[:lookupBytes]))
	secret := material[lookupBytes:]
	hash = sha256.Sum256(secret)
	token = prefix + lookupID.String() + "." + base64.RawURLEncoding.EncodeToString(secret)
	return token, lookupID, hash, nil
}

func parseToken(token, prefix string, invalid error) (CredentialID, SecretHash, error) {
	body, ok := strings.CutPrefix(token, prefix)
	if !ok {
		return "", SecretHash{}, invalid
	}
	encodedID, encodedSecret, ok := strings.Cut(body, ".")
	if !ok || strings.Contains(encodedSecret, ".") {
		return "", SecretHash{}, invalid
	}
	id, err := base64.RawURLEncoding.DecodeString(encodedID)
	if err != nil || len(id) != lookupBytes || base64.RawURLEncoding.EncodeToString(id) != encodedID {
		return "", SecretHash{}, invalid
	}
	secret, err := base64.RawURLEncoding.DecodeString(encodedSecret)
	if err != nil || len(secret) != secretBytes || base64.RawURLEncoding.EncodeToString(secret) != encodedSecret {
		return "", SecretHash{}, invalid
	}
	return CredentialID(encodedID), sha256.Sum256(secret), nil
}

// SecretHashMatches compares a stored digest without data-dependent timing.
func SecretHashMatches(stored []byte, candidate SecretHash) bool {
	return subtle.ConstantTimeCompare(stored, candidate[:]) == 1
}
