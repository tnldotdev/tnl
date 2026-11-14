package visitortoken

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

const (
	ClearanceType     = "tnl-challenge-clearance+jwt"
	ClearancePurpose  = "http_protection"
	ClearanceLifetime = 30 * time.Minute
)

// ClearanceToken proves challenge completion only. no visitor permission can
// be constructed from it, and it carries no run or policy revision.
type ClearanceToken string

func (ClearanceToken) String() string   { return "challenge clearance" }
func (ClearanceToken) GoString() string { return "challenge clearance" }
func (t ClearanceToken) Reveal() string { return string(t) }

type Clearance struct {
	Scope     visitorscope.Scope
	Hostname  string
	Port      uint16
	ExpiresAt time.Time
}

type clearanceClaims struct {
	ID      string             `json:"jti"`
	Version int                `json:"version"`
	Issuer  string             `json:"iss"`
	Purpose string             `json:"purpose"`
	Scope   visitorscope.Scope `json:"scope"`
	Origin  string             `json:"origin"`
	Issued  int64              `json:"iat"`
	Expires int64              `json:"exp"`
}

func ClearanceOrigin(hostname string, port uint16) string {
	authority := hostname
	if port != 443 {
		authority = net.JoinHostPort(hostname, strconv.Itoa(int(port)))
	}
	return "https://" + authority
}

func SignClearance(issuer, keyID string, private ed25519.PrivateKey, clearance Clearance, now time.Time) (ClearanceToken, error) {
	if !validText(issuer, 256) || !validText(keyID, 128) || len(private) != ed25519.PrivateKeySize ||
		!validResource(clearance.Scope, clearance.Hostname, clearance.Port) || !clearance.ExpiresAt.After(now) ||
		clearance.ExpiresAt.After(now.Add(ClearanceLifetime)) || clearance.ExpiresAt.Unix() <= now.Unix() {
		return "", ErrToken
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ErrToken
	}
	payload, err := json.Marshal(clearanceClaims{ID: base64.RawURLEncoding.EncodeToString(nonce[:]), Version: 1, Issuer: issuer, Purpose: ClearancePurpose,
		Scope: clearance.Scope, Origin: ClearanceOrigin(clearance.Hostname, clearance.Port), Issued: now.Unix(), Expires: clearance.ExpiresAt.Unix()})
	if err != nil {
		return "", ErrToken
	}
	raw, err := signCredential(ClearanceType, keyID, private, payload)
	return ClearanceToken(raw), err
}

// VerifyClearance requires a fresh run-owned key view, but clearance itself is
// independent of the run, authorization revision, source IP, and WAF settings.
// the caller must still apply ordinary visitor authorization and request limits.
func VerifyClearance(token ClearanceToken, view View, now time.Time) (time.Time, error) {
	payload, _, err := verifyCredential(token.Reveal(), ClearanceType, view, now)
	if err != nil {
		return time.Time{}, err
	}
	var value clearanceClaims
	at := view.AuthorityTime(now).Unix()
	if decode(payload, &value) != nil || value.Version != 1 || value.Issuer != view.Issuer || value.Purpose != ClearancePurpose ||
		value.Scope != view.Scope || value.Origin != ClearanceOrigin(view.Hostname, view.Port) ||
		value.Issued <= 0 || value.Issued > at || value.Expires <= at || value.Expires <= value.Issued ||
		value.Expires-value.Issued > int64(ClearanceLifetime/time.Second) {
		return time.Time{}, ErrToken
	}
	if nonce, err := base64.RawURLEncoding.Strict().DecodeString(value.ID); err != nil || len(nonce) != 16 {
		return time.Time{}, ErrToken
	}
	return view.LocalDeadline(time.Unix(value.Expires, 0).UTC()), nil
}
