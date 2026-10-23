// package visitortoken owns the signed visitor credential and local verification.
// control supplies authorized facts; serving owners supply current policy views.
// this leaf has no membership, grant, routing, capacity, or network authority.
package visitortoken

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// Subject is closed to the credential variants issued by control. these facts
// identify visitor authority, never verified feedback authorship.
type Subject interface {
	visitorSubject() string
	valid() bool
}

type Browser struct {
	IdentityID string `json:"identity_id"`
	SessionID  string `json:"session_id"`
}

func (Browser) visitorSubject() string { return "browser" }
func (s Browser) valid() bool {
	return opaqueid.Valid(s.IdentityID, opaqueid.IdentityPrefix) && opaqueid.Valid(s.SessionID, opaqueid.ControlSessionPrefix)
}

type Share struct {
	ShareID string `json:"share_id"`
}

func (Share) visitorSubject() string { return "share" }
func (s Share) valid() bool          { return opaqueid.Valid(s.ShareID, opaqueid.SharePrefix) }

type Grant struct {
	GrantID string `json:"grant_id"`
}

func (Grant) visitorSubject() string { return "grant" }
func (s Grant) valid() bool          { return opaqueid.Valid(s.GrantID, "shg_") }

type Device struct {
	IdentityID string `json:"identity_id"`
	SessionID  string `json:"session_id"`
	DeviceID   string `json:"device_id"`
	KeySHA256  string `json:"key_sha256"`
}

func (Device) visitorSubject() string { return "device" }
func (s Device) valid() bool {
	return (Browser{IdentityID: s.IdentityID, SessionID: s.SessionID}).valid() && opaqueid.Valid(s.DeviceID, opaqueid.VisitorDevicePrefix) && validKeyDigest(s.KeySHA256)
}

type Workload struct {
	SessionID string `json:"workload_session_id"`
	KeySHA256 string `json:"key_sha256"`
}

func (Workload) visitorSubject() string { return "workload" }
func (s Workload) valid() bool {
	return opaqueid.Valid(s.SessionID, "wls_") && validKeyDigest(s.KeySHA256)
}

// Certificate binds the same permission contract to a control-issued TLS key.
// its serial references the existing certificate owner's durable parent facts.
type Certificate struct {
	Serial    string  `json:"serial"`
	KeySHA256 string  `json:"key_sha256"`
	Source    Subject `json:"-"`
}

func (Certificate) visitorSubject() string { return "certificate" }
func (s Certificate) valid() bool {
	switch s.Source.(type) {
	case Device, Workload:
	default:
		return false
	}
	return s.Source.valid() && len(s.Serial) > 0 && len(s.Serial) <= 64 && strings.Trim(s.Serial, "0123456789abcdef") == "" && validKeyDigest(s.KeySHA256)
}

type certificateSubject struct {
	Serial    string          `json:"serial"`
	KeySHA256 string          `json:"key_sha256"`
	Source    json.RawMessage `json:"source"`
}

func (s Certificate) MarshalJSON() ([]byte, error) {
	if !s.valid() {
		return nil, ErrToken
	}
	source, err := encodeSubject(s.Source)
	if err != nil {
		return nil, err
	}
	return json.Marshal(certificateSubject{Serial: s.Serial, KeySHA256: s.KeySHA256, Source: source})
}

func validKeyDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

// KeyDigest uses SPKI for both native Ed25519 keys and TLS client keys.
func KeyDigest(public any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return "", ErrBinding
	}
	digest := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

type subjectEnvelope struct {
	Kind  string          `json:"kind"`
	Value json.RawMessage `json:"value"`
}

func encodeSubject(subject Subject) (json.RawMessage, error) {
	switch subject.(type) {
	case Browser, Share, Grant, Device, Workload, Certificate:
	default:
		return nil, ErrToken
	}
	if subject == nil || !subject.valid() {
		return nil, ErrToken
	}
	body, err := json.Marshal(subject)
	if err != nil {
		return nil, ErrToken
	}
	return json.Marshal(subjectEnvelope{Kind: subject.visitorSubject(), Value: body})
}

func decodeSubject(data json.RawMessage) (Subject, error) {
	var envelope subjectEnvelope
	if decode(data, &envelope) != nil {
		return nil, ErrToken
	}
	var subject Subject
	switch envelope.Kind {
	case "browser":
		var value Browser
		if decode(envelope.Value, &value) != nil {
			return nil, ErrToken
		}
		subject = value
	case "share":
		var value Share
		if decode(envelope.Value, &value) != nil {
			return nil, ErrToken
		}
		subject = value
	case "grant":
		var value Grant
		if decode(envelope.Value, &value) != nil {
			return nil, ErrToken
		}
		subject = value
	case "device":
		var value Device
		if decode(envelope.Value, &value) != nil {
			return nil, ErrToken
		}
		subject = value
	case "workload":
		var value Workload
		if decode(envelope.Value, &value) != nil {
			return nil, ErrToken
		}
		subject = value
	case "certificate":
		var value certificateSubject
		if decode(envelope.Value, &value) != nil {
			return nil, ErrToken
		}
		var sourceEnvelope subjectEnvelope
		if decode(value.Source, &sourceEnvelope) != nil || (sourceEnvelope.Kind != "device" && sourceEnvelope.Kind != "workload") {
			return nil, ErrToken
		}
		source, err := decodeSubject(value.Source)
		if err != nil {
			return nil, err
		}
		subject = Certificate{Serial: value.Serial, KeySHA256: value.KeySHA256, Source: source}
	default:
		return nil, ErrToken
	}
	if !subject.valid() {
		return nil, ErrToken
	}
	return subject, nil
}
