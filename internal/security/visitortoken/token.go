package visitortoken

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

const (
	Type              = "tnl-visitor+jwt"
	MaxTokenBytes     = 2048
	PolicyLifetime    = 10 * time.Second
	RenewableLifetime = 5 * time.Minute
)

var (
	ErrToken   = errors.New("visitor token is invalid")
	ErrPolicy  = errors.New("visitor policy is stale")
	ErrKey     = errors.New("visitor verification key is unavailable")
	ErrBinding = errors.New("visitor token binding is invalid")
)

// Token redacts incidental formatting. only the credential's wire owner reveals it.
type Token string

func (Token) String() string   { return "visitor token" }
func (Token) GoString() string { return "visitor token" }
func (t Token) Reveal() string { return string(t) }

type Permission struct {
	SigningKeyID          string
	Scope                 visitorscope.Scope
	Hostname              string
	Port                  uint16
	VisitorPolicyRevision int64
	Subject               Subject
	ExpiresAt             time.Time
}

type claims struct {
	Version  int                `json:"version"`
	Issuer   string             `json:"iss"`
	Scope    visitorscope.Scope `json:"scope"`
	Hostname string             `json:"hostname"`
	Port     uint16             `json:"port"`
	Revision int64              `json:"visitor_policy_revision"`
	Issued   int64              `json:"iat"`
	Expires  int64              `json:"exp"`
	Subject  json.RawMessage    `json:"visitor"`
}

type protectedHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func validResource(scope visitorscope.Scope, hostname string, port uint16) bool {
	canonical, err := naming.CanonicalizeHostname(hostname)
	return err == nil && canonical == hostname && !strings.Contains(hostname, "*") && scope.Valid() && port != 0 && (scope.Kind != visitorscope.PublicURL || port == 443)
}

// Sign receives a decision already authorized by control. the supplied deadline
// must be capped by every parent; renewable callers also cap it at five minutes.
func Sign(issuer, keyID string, private ed25519.PrivateKey, permission Permission, now time.Time) (Token, error) {
	if !validText(issuer, 256) || !validText(keyID, 128) || len(private) != ed25519.PrivateKeySize ||
		!validResource(permission.Scope, permission.Hostname, permission.Port) || permission.VisitorPolicyRevision < 1 || !permission.ExpiresAt.After(now) || permission.ExpiresAt.Unix() <= now.Unix() {
		return "", ErrToken
	}
	visitor, err := encodeSubject(permission.Subject)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims{Version: 1, Issuer: issuer, Scope: permission.Scope, Hostname: permission.Hostname, Port: permission.Port,
		Revision: permission.VisitorPolicyRevision, Issued: now.Unix(), Expires: permission.ExpiresAt.Unix(), Subject: visitor})
	if err != nil {
		return "", ErrToken
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: private}, (&jose.SignerOptions{}).WithType(Type).WithHeader("kid", keyID))
	if err != nil {
		return "", ErrToken
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", ErrToken
	}
	raw, err := signed.CompactSerialize()
	if err != nil || len(raw) > MaxTokenBytes {
		return "", ErrToken
	}
	return Token(raw), nil
}

// View is an immutable, authenticated projection supplied by a serving owner.
// observation uses the request-start time, not when a slow renewal completes.
// a process lease never substitutes for this policy deadline.
type View struct {
	Issuer                string
	Scope                 visitorscope.Scope
	Hostname              string
	Port                  uint16
	VisitorPolicyRevision int64
	ObservedAt            time.Time
	ValidUntil            time.Time
	Keys                  map[string]ed25519.PublicKey
	ControlTime           time.Time
	Workloads             map[string]WorkloadLease
}

type WorkloadLease struct {
	KeySHA256 string
	ExpiresAt time.Time
}

// AuthorityTime uses elapsed local time from the policy request's start. it
// advances conservatively through network delay without trusting clock skew.
func (v View) AuthorityTime(now time.Time) time.Time {
	if v.ControlTime.IsZero() {
		return now
	}
	return v.ControlTime.Add(max(0, now.Sub(v.ObservedAt)))
}

func (v View) LocalDeadline(deadline time.Time) time.Time {
	if v.ControlTime.IsZero() {
		return deadline
	}
	return v.ObservedAt.Add(deadline.Sub(v.ControlTime))
}

func (v View) current(now time.Time) bool {
	return validText(v.Issuer, 256) && validResource(v.Scope, v.Hostname, v.Port) && v.VisitorPolicyRevision > 0 &&
		!v.ObservedAt.IsZero() && !now.Before(v.ObservedAt) && v.ValidUntil.After(v.ObservedAt) && !v.ValidUntil.After(v.ObservedAt.Add(PolicyLifetime)) && now.Before(v.ValidUntil)
}

func verify(token Token, view View, now time.Time) (Permission, error) {
	if !view.current(now) {
		return Permission{}, ErrPolicy
	}
	authorityNow := view.AuthorityTime(now)
	raw := token.Reveal()
	if len(raw) == 0 || len(raw) > MaxTokenBytes {
		return Permission{}, ErrToken
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Permission{}, ErrToken
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	var header protectedHeader
	if err != nil || decode(headerBytes, &header) != nil || header.Algorithm != string(jose.EdDSA) || header.Type != Type || !validText(header.KeyID, 128) {
		return Permission{}, ErrToken
	}
	public := view.Keys[header.KeyID]
	if len(public) != ed25519.PublicKeySize {
		return Permission{}, ErrKey
	}
	signed, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil || len(signed.Signatures) != 1 {
		return Permission{}, ErrToken
	}
	payload, err := signed.Verify(public)
	if err != nil {
		return Permission{}, ErrToken
	}
	var value claims
	if decode(payload, &value) != nil || value.Version != 1 || value.Issuer != view.Issuer || value.Scope != view.Scope || value.Hostname != view.Hostname || value.Port != view.Port ||
		value.Revision != view.VisitorPolicyRevision || value.Issued > authorityNow.Unix() || value.Issued <= 0 || value.Expires <= value.Issued || value.Expires <= authorityNow.Unix() {
		return Permission{}, ErrToken
	}
	subject, err := decodeSubject(value.Subject)
	if err != nil {
		return Permission{}, err
	}
	permission := Permission{SigningKeyID: header.KeyID, Scope: value.Scope, Hostname: value.Hostname, Port: value.Port, VisitorPolicyRevision: value.Revision, Subject: subject, ExpiresAt: time.Unix(value.Expires, 0).UTC()}
	if err := CheckCurrent(permission, view, now); err != nil {
		return Permission{}, err
	}
	return permission, nil
}

// CheckCurrent rechecks an already verified, proof-bound admission. it does not
// replace signature or possession verification at the admission boundary.
func CheckCurrent(permission Permission, view View, now time.Time) error {
	if !view.current(now) {
		return ErrPolicy
	}
	if permission.Scope != view.Scope || permission.Hostname != view.Hostname || permission.Port != view.Port || permission.VisitorPolicyRevision != view.VisitorPolicyRevision || !permission.ExpiresAt.After(view.AuthorityTime(now)) {
		return ErrToken
	}
	if len(view.Keys[permission.SigningKeyID]) != ed25519.PublicKeySize {
		return ErrKey
	}
	subject := permission.Subject
	if certificate, ok := subject.(Certificate); ok {
		subject = certificate.Source
	}
	if workload, ok := subject.(Workload); ok {
		parent, found := view.Workloads[workload.SessionID]
		if !found || parent.KeySHA256 != workload.KeySHA256 || !parent.ExpiresAt.After(view.AuthorityTime(now)) {
			return ErrBinding
		}
	}
	return nil
}

func VerifyBearer(token Token, view View, now time.Time) (Permission, error) {
	permission, err := verify(token, view, now)
	if err != nil {
		return Permission{}, err
	}
	switch permission.Subject.(type) {
	case Browser, Share, Grant:
		return permission, nil
	default:
		return Permission{}, ErrBinding
	}
}

// decode rejects unknown fields, duplicate members, trailing values, excessive
// nesting and non-objects. the signature is checked before parsing claims.
func decode(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var object func(int) error
	object = func(depth int) error {
		if depth > 8 {
			return ErrToken
		}
		token, err := decoder.Token()
		if err != nil || token != json.Delim('{') {
			return ErrToken
		}
		seen := make(map[string]bool)
		for decoder.More() {
			name, err := decoder.Token()
			key, ok := name.(string)
			if err != nil || !ok || seen[key] {
				return ErrToken
			}
			seen[key] = true
			var value json.RawMessage
			if decoder.Decode(&value) != nil {
				return ErrToken
			}
			if len(value) > 0 && value[0] == '{' {
				saved := decoder
				decoder = json.NewDecoder(bytes.NewReader(value))
				err = object(depth + 1)
				decoder = saved
				if err != nil {
					return err
				}
			}
		}
		_, err = decoder.Token()
		return err
	}
	if object(0) != nil {
		return ErrToken
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrToken
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return ErrToken
	}
	return nil
}
