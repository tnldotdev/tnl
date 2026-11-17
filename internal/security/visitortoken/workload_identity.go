package visitortoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitorcert"
)

const (
	WorkloadIdentityType  = "tnl-workload-identity+jwt"
	WorkloadLeaseLifetime = 90 * time.Second
)

// WorkloadIdentity is control's fixed certificate identity, not visitor permission.
// the distinct signed profile cannot authorize a bearer or a device certificate.
type WorkloadIdentity struct {
	Issuer       string
	SigningKeyID string
	Scope        visitorscope.Scope
	Hostname     string
	Port         uint16
	Certificate  Certificate
	ExpiresAt    time.Time
}

type workloadIdentityClaims struct {
	ID       string             `json:"jti"`
	Version  int                `json:"version"`
	Issuer   string             `json:"iss"`
	Scope    visitorscope.Scope `json:"scope"`
	Hostname string             `json:"hostname"`
	Port     uint16             `json:"port"`
	Issued   int64              `json:"iat"`
	Expires  int64              `json:"exp"`
	Subject  json.RawMessage    `json:"visitor"`
}

func (i WorkloadIdentity) valid() bool {
	workload, ok := i.Certificate.Source.(Workload)
	return ok && i.Scope.Kind == visitorscope.Service && validResource(i.Scope, i.Hostname) &&
		i.Certificate.valid() && i.Certificate.KeySHA256 == workload.KeySHA256
}

func SignWorkloadIdentity(issuer, keyID string, private ed25519.PrivateKey, identity WorkloadIdentity, now time.Time) (Token, error) {
	if !validText(issuer, 256) || !validText(keyID, 128) || len(private) != ed25519.PrivateKeySize || !identity.valid() ||
		identity.Issuer != "" && identity.Issuer != issuer ||
		identity.ExpiresAt.Unix() <= now.Unix() || identity.ExpiresAt.After(now.Add(visitorcert.MaxWorkloadLifetime)) {
		return "", ErrToken
	}
	subject, err := encodeSubject(identity.Certificate)
	if err != nil {
		return "", err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ErrToken
	}
	payload, err := json.Marshal(workloadIdentityClaims{ID: base64.RawURLEncoding.EncodeToString(nonce[:]), Version: 1, Issuer: issuer,
		Scope: identity.Scope, Hostname: identity.Hostname, Port: identity.Port, Issued: now.Unix(), Expires: identity.ExpiresAt.Unix(), Subject: subject})
	if err != nil {
		return "", ErrToken
	}
	return signPayload(WorkloadIdentityType, keyID, private, payload)
}

func decodeWorkloadIdentity(payload []byte) (WorkloadIdentity, workloadIdentityClaims, error) {
	var value workloadIdentityClaims
	if decode(payload, &value) != nil || value.Version != 1 || !validText(value.Issuer, 256) || value.Issued <= 0 || value.Expires <= value.Issued ||
		value.Expires-value.Issued > int64(visitorcert.MaxWorkloadLifetime/time.Second) {
		return WorkloadIdentity{}, value, ErrToken
	}
	if nonce, err := base64.RawURLEncoding.Strict().DecodeString(value.ID); err != nil || len(nonce) != 16 {
		return WorkloadIdentity{}, value, ErrToken
	}
	subject, err := decodeSubject(value.Subject)
	certificate, ok := subject.(Certificate)
	identity := WorkloadIdentity{Issuer: value.Issuer, Scope: value.Scope, Hostname: value.Hostname, Port: value.Port, Certificate: certificate, ExpiresAt: time.Unix(value.Expires, 0).UTC()}
	if err != nil || !ok || !identity.valid() {
		return WorkloadIdentity{}, value, ErrToken
	}
	return identity, value, nil
}

func verifyWorkloadIdentity(token Token, view View, state tls.ConnectionState, now time.Time) (VerifiedPermission, error) {
	payload, keyID, err := verifyPayload(token, view, WorkloadIdentityType, now)
	if err != nil {
		return VerifiedPermission{}, err
	}
	identity, value, err := decodeWorkloadIdentity(payload)
	if err != nil || value.Issuer != view.Issuer || value.Issued > view.AuthorityTime(now).Unix() {
		return VerifiedPermission{}, ErrToken
	}
	identity.SigningKeyID = keyID
	if err := certificateBinding(token, identity.Certificate, identity.ExpiresAt, state, view, now); err != nil {
		return VerifiedPermission{}, err
	}
	if !identity.ExpiresAt.Equal(state.PeerCertificates[0].NotAfter) {
		return VerifiedPermission{}, ErrBinding
	}
	return currentWorkloadPermission(identity, view, now)
}

// WorkloadPermission is short, validated control evidence for an exact verified
// certificate identity. only authenticated policy can replace its current lease.
type WorkloadPermission struct {
	identity WorkloadIdentity
	facts    Permission
}

func (p VerifiedPermission) WorkloadPermission() (WorkloadPermission, bool) {
	if p.workload == nil {
		return WorkloadPermission{}, false
	}
	return *p.workload, true
}

func (p WorkloadPermission) Identity() WorkloadIdentity { return p.identity }

func (p WorkloadPermission) checkCurrent(view View, now time.Time) error {
	if err := p.identity.current(view, now); err != nil {
		return err
	}
	return checkCurrent(p.facts, view, now)
}

func (i WorkloadIdentity) current(view View, now time.Time) error {
	if !view.current(now) {
		return ErrPolicy
	}
	if !i.valid() || i.SigningKeyID == "" || !view.HasSigningKey(i.SigningKeyID) {
		return ErrKey
	}
	if i.Issuer != view.Issuer || i.Scope != view.Scope || i.Hostname != view.Hostname || i.Port != view.Port || !i.ExpiresAt.After(view.AuthorityTime(now)) {
		return ErrBinding
	}
	return nil
}

func currentWorkloadPermission(identity WorkloadIdentity, view View, now time.Time) (VerifiedPermission, error) {
	if err := identity.current(view, now); err != nil {
		return VerifiedPermission{}, err
	}
	workload := identity.Certificate.Source.(Workload)
	parent, found := view.Workload(workload.SessionID)
	observed := view.ControlTime
	if observed.IsZero() {
		observed = view.ObservedAt
	}
	if !found || parent.KeySHA256 != workload.KeySHA256 || !parent.ExpiresAt.After(view.AuthorityTime(now)) ||
		parent.ExpiresAt.After(observed.Add(WorkloadLeaseLifetime)) {
		return VerifiedPermission{}, ErrBinding
	}
	until := parent.ExpiresAt
	if identity.ExpiresAt.Before(until) {
		until = identity.ExpiresAt
	}
	permission := Permission{SigningKeyID: identity.SigningKeyID, Scope: identity.Scope, Hostname: identity.Hostname, Port: identity.Port,
		VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: identity.Certificate, ExpiresAt: until}
	current := &WorkloadPermission{identity: identity, facts: permission}
	return VerifiedPermission{facts: permission, workload: current}, nil
}

// Renew requires still-live previous evidence. the guard owner additionally
// checks its retained local deadline before installing this fresh policy result.
func (p WorkloadPermission) Renew(view View, now time.Time) (VerifiedPermission, error) {
	if !p.facts.ExpiresAt.After(view.AuthorityTime(now)) {
		return VerifiedPermission{}, ErrPolicy
	}
	return currentWorkloadPermission(p.identity, view, now)
}
