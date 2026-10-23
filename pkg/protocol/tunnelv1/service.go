package tunnelv1

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// private forwarding includes up to three configured 256-byte process IDs,
// each of which may expand sixfold in JSON, plus fixed opaque IDs and metadata.
const MaxServiceHeaderBytes = 8 << 10

// ConnectorSessionHello authenticates one TLS-protected infrastructure
// mux session. ingress binds the claimed session to its observed source IP;
// this credential never admits a visitor stream by itself.
type ConnectorSessionHello struct {
	ProtocolVersion uint32         `json:"protocol_version"`
	Kind            string         `json:"kind"`
	ServiceID       string         `json:"service_id"`
	SessionID       string         `json:"connector_session_id"`
	Credential      string         `json:"session_credential"`
	Subject         VisitorSubject `json:"subject"`
	Nonce           []byte         `json:"nonce"`
	Signature       []byte         `json:"signature"`
}

func (h ConnectorSessionHello) Validate() error {
	if h.ProtocolVersion != Version || h.Kind != "connector_session" ||
		!opaqueid.Valid(h.ServiceID, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(h.SessionID, opaqueid.ConnectorSessionPrefix) ||
		!validCredential(h.Credential) || len(h.Credential) != 43 || h.Subject.Validate() != nil ||
		len(h.Nonce) != 32 || len(h.Signature) != ed25519.SignatureSize {
		return errors.New("tunnelv1: invalid private connector session hello")
	}
	return nil
}

func WriteConnectorSessionHello(w io.Writer, h ConnectorSessionHello) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, h, MaxServiceHeaderBytes)
}

func ReadConnectorSessionHello(r io.Reader) (ConnectorSessionHello, error) {
	var h ConnectorSessionHello
	if err := readJSONFrame(r, &h, MaxServiceHeaderBytes); err != nil {
		return ConnectorSessionHello{}, err
	}
	if err := h.Validate(); err != nil {
		return ConnectorSessionHello{}, err
	}
	return h, nil
}

// ConnectorSessionAccepted is ingress-authenticated session state. the
// observed source comes from ingress's socket or verified PROXY metadata.
type ConnectorSessionAccepted struct {
	ProtocolVersion uint32         `json:"protocol_version"`
	Kind            string         `json:"kind"`
	ServiceID       string         `json:"service_id"`
	SessionID       string         `json:"connector_session_id"`
	Subject         VisitorSubject `json:"subject"`
	SourceIP        string         `json:"source_ip"`
	ExpiresAt       time.Time      `json:"expires_at"`
}

func (a ConnectorSessionAccepted) Validate() error {
	if a.ProtocolVersion != Version || a.Kind != "connector_session_accepted" ||
		!opaqueid.Valid(a.ServiceID, opaqueid.ServicePrefix) || !opaqueid.Valid(a.SessionID, opaqueid.ConnectorSessionPrefix) ||
		a.Subject.Validate() != nil || !validPrivateSourceIP(a.SourceIP) || a.ExpiresAt.IsZero() {
		return errors.New("tunnelv1: invalid private connector session acceptance")
	}
	return nil
}

func WriteConnectorSessionAccepted(w io.Writer, a ConnectorSessionAccepted) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, a, MaxServiceHeaderBytes)
}

func ReadConnectorSessionAccepted(r io.Reader) (ConnectorSessionAccepted, error) {
	var a ConnectorSessionAccepted
	if err := readJSONFrame(r, &a, MaxServiceHeaderBytes); err != nil {
		return a, err
	}
	return a, a.Validate()
}

// ConnectorVisitorEntry starts each visitor stream within an authenticated mux
// session. ingress authorizes this exact service/run against the enrolled
// session identity and trusted source before forwarding any bytes.
// no client-supplied IP or untrusted SNI selects a service.
type ConnectorVisitorEntry struct {
	TraceContext        TraceContext            `json:"trace_context,omitzero"`
	ProtocolVersion     uint32                  `json:"protocol_version"`
	Kind                StreamKind              `json:"kind"`
	ServiceID           string                  `json:"service_id"`
	ServiceRunID        string                  `json:"service_run_id"`
	RunNumber           uint64                  `json:"run_number"`
	VisitorConnectionID string                  `json:"visitor_connection_id"`
	MetadataRevision    uint64                  `json:"metadata_revision"`
	Permission          NativeVisitorPermission `json:"permission"`
}

// NativeVisitorPermission carries a signed visit and proof for one opening.
// its key must match the signed subject and the authenticated connector session.
type NativeVisitorPermission struct {
	Token     string `json:"visitor_token"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func (NativeVisitorPermission) String() string   { return "native visitor permission" }
func (NativeVisitorPermission) GoString() string { return "native visitor permission" }

func (p NativeVisitorPermission) valid() bool {
	public, keyErr := base64.RawURLEncoding.Strict().DecodeString(p.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(p.Signature)
	return len(p.Token) > 0 && len(p.Token) <= 2048 && validCredential(p.Token) && keyErr == nil && signatureErr == nil && len(public) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize
}

func (e ConnectorVisitorEntry) Validate() error {
	if err := e.TraceContext.Validate(); err != nil {
		return err
	}
	if e.ProtocolVersion != Version || e.Kind != ConnectorVisitorStream ||
		!opaqueid.Valid(e.ServiceID, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(e.ServiceRunID, opaqueid.ServiceRunPrefix) ||
		e.RunNumber == 0 || e.RunNumber > math.MaxInt64 ||
		!opaqueid.Valid(e.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) || e.MetadataRevision == 0 || e.MetadataRevision > math.MaxInt64 || !e.Permission.valid() {
		return errors.New("tunnelv1: invalid private visitor entry")
	}
	return nil
}

// ConnectorVisitorAccepted carries ingress's trusted, claimed stream identity
// back to the connector before inner TLS. the connector compares session and
// source with the authenticated session. the publisher receives the
// same admitted identity in ServiceStreamHeader and rechecks it with control.
type ConnectorVisitorAccepted struct {
	ProtocolVersion              uint32         `json:"protocol_version"`
	Kind                         string         `json:"kind"`
	ConnectorSessionID           string         `json:"connector_session_id"`
	Subject                      VisitorSubject `json:"subject"`
	SourceIP                     string         `json:"source_ip"`
	VisitorConnectionID          string         `json:"visitor_connection_id"`
	GrantRevision                uint64         `json:"grant_revision"`
	PublisherConnectionID        string         `json:"publisher_connection_id"`
	ConnectionAssignmentRevision uint64         `json:"connection_assignment_revision"`
}

func (a ConnectorVisitorAccepted) Validate() error {
	if a.ProtocolVersion != Version || a.Kind != "connector_visitor_accepted" ||
		!opaqueid.Valid(a.ConnectorSessionID, opaqueid.ConnectorSessionPrefix) ||
		a.Subject.Validate() != nil || !validPrivateSourceIP(a.SourceIP) ||
		!opaqueid.Valid(a.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) || a.GrantRevision == 0 ||
		!opaqueid.Valid(a.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) || a.ConnectionAssignmentRevision == 0 {
		return errors.New("tunnelv1: invalid private visitor acceptance")
	}
	return nil
}

func WriteConnectorVisitorAccepted(w io.Writer, a ConnectorVisitorAccepted) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, a, MaxServiceHeaderBytes)
}

func ReadConnectorVisitorAccepted(r io.Reader) (ConnectorVisitorAccepted, error) {
	var a ConnectorVisitorAccepted
	if err := readJSONFrame(r, &a, MaxServiceHeaderBytes); err != nil {
		return ConnectorVisitorAccepted{}, err
	}
	if err := a.Validate(); err != nil {
		return ConnectorVisitorAccepted{}, err
	}
	return a, nil
}

func WriteConnectorVisitorEntry(w io.Writer, e ConnectorVisitorEntry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, e, MaxServiceHeaderBytes)
}

func ReadConnectorVisitorEntry(r io.Reader) (ConnectorVisitorEntry, error) {
	var e ConnectorVisitorEntry
	if err := readJSONFrame(r, &e, MaxServiceHeaderBytes); err != nil {
		return ConnectorVisitorEntry{}, err
	}
	if err := e.Validate(); err != nil {
		return ConnectorVisitorEntry{}, err
	}
	return e, nil
}

// ServiceStreamHeader is trusted ingress state forwarded through a relay.
// compare its IDs, assignment and grant revisions with the claimed run;
// never permit a public URL connection reference on this stream.
type ServiceStreamHeader struct {
	TraceContext                 TraceContext        `json:"trace_context,omitzero"`
	ProtocolVersion              uint32              `json:"protocol_version"`
	Kind                         StreamKind          `json:"kind"`
	ServiceID                    string              `json:"service_id"`
	ServiceRunID                 string              `json:"service_run_id"`
	Connector                    *ConnectorAdmission `json:"connector,omitempty"`
	Direct                       *DirectAdmission    `json:"direct,omitempty"`
	SourceIP                     string              `json:"source_ip"`
	RunNumber                    uint64              `json:"run_number"`
	VisitorConnectionID          string              `json:"visitor_connection_id"`
	PublisherConnectionID        string              `json:"publisher_connection_id"`
	ConnectionAssignmentRevision uint64              `json:"connection_assignment_revision"`
	ExpiresAt                    time.Time           `json:"expires_at"`
}

// ConnectorAdmission is an authenticated identity selected by ingress. direct
// admission has no visitor identity until the publisher authenticates the client.
type ConnectorAdmission struct {
	SessionID     string         `json:"session_id"`
	Subject       VisitorSubject `json:"subject"`
	GrantRevision uint64         `json:"grant_revision"`
}

type DirectAdmission struct {
	IngressID            string `json:"ingress_id"`
	IngressRunID         string `json:"ingress_run_id"`
	IngressLeaseRevision uint64 `json:"ingress_lease_revision"`
	DestinationPort      uint16 `json:"destination_port"`
}

func (a ConnectorAdmission) valid() bool {
	return opaqueid.Valid(a.SessionID, opaqueid.ConnectorSessionPrefix) &&
		a.Subject.Validate() == nil && a.GrantRevision > 0
}

func (a DirectAdmission) valid() bool {
	return validIdentifier(a.IngressID) && opaqueid.Valid(a.IngressRunID, opaqueid.IngressRunPrefix) && a.IngressLeaseRevision > 0 && a.DestinationPort >= 1024
}

func (h ServiceStreamHeader) Validate() error {
	return h.validate(ConnectorVisitorStream)
}

func (h ServiceStreamHeader) validate(kind StreamKind) error {
	if err := h.TraceContext.Validate(); err != nil {
		return err
	}
	if h.ProtocolVersion != Version || h.Kind != kind ||
		!opaqueid.Valid(h.ServiceID, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(h.ServiceRunID, opaqueid.ServiceRunPrefix) || h.RunNumber == 0 ||
		!validPrivateSourceIP(h.SourceIP) ||
		!opaqueid.Valid(h.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) ||
		!opaqueid.Valid(h.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) ||
		h.ConnectionAssignmentRevision == 0 || h.ExpiresAt.IsZero() ||
		(h.Connector == nil) == (h.Direct == nil) || h.Connector != nil && !h.Connector.valid() || h.Direct != nil && !h.Direct.valid() {
		return errors.New("tunnelv1: invalid private stream header")
	}
	return nil
}

func validPrivateSourceIP(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.IsValid() && addr.Zone() == "" && addr.String() == value
}

// ServiceForwardingHeader carries the current relay lease along with the
// already authorized service/run/subject binding. it never accepts public URL IDs.
type ServiceForwardingHeader struct {
	ServiceStreamHeader
	ConnectionSlot     uint8     `json:"connection_slot"`
	RelayServiceID     string    `json:"relay_service_id"`
	RelayID            string    `json:"relay_id"`
	RelayRunID         string    `json:"relay_run_id"`
	RelayLeaseRevision uint64    `json:"relay_lease_revision"`
	LeaseExpiresAt     time.Time `json:"lease_expires_at"`
}

func (h ServiceForwardingHeader) Validate() error {
	if err := h.ServiceStreamHeader.validate(ServiceForwardingStream); err != nil {
		return err
	}
	if h.ConnectionSlot > 1 || !validIdentifier(h.RelayServiceID) || !validIdentifier(h.RelayID) ||
		!opaqueid.Valid(h.RelayRunID, opaqueid.RelayRunPrefix) || h.RelayLeaseRevision == 0 || h.LeaseExpiresAt.IsZero() {
		return errors.New("tunnelv1: invalid private forwarding header")
	}
	return nil
}

func WriteServiceForwardingHeader(w io.Writer, h ServiceForwardingHeader) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, h, MaxServiceHeaderBytes)
}

func ReadServiceForwardingHeader(r io.Reader) (ServiceForwardingHeader, error) {
	var h ServiceForwardingHeader
	if err := readJSONFrame(r, &h, MaxServiceHeaderBytes); err != nil {
		return ServiceForwardingHeader{}, err
	}
	if err := h.Validate(); err != nil {
		return ServiceForwardingHeader{}, err
	}
	return h, nil
}

func WriteServiceStreamHeader(w io.Writer, h ServiceStreamHeader) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, h, MaxServiceHeaderBytes)
}

func ReadServiceStreamHeader(r io.Reader) (ServiceStreamHeader, error) {
	var h ServiceStreamHeader
	if err := readJSONFrame(r, &h, MaxServiceHeaderBytes); err != nil {
		return ServiceStreamHeader{}, err
	}
	if err := h.Validate(); err != nil {
		return ServiceStreamHeader{}, err
	}
	return h, nil
}

// Claim binds the proof to the subject and exact one-use assignment.
func (hello ConnectorSessionHello) Claim() VisitorConnectorClaim {
	return VisitorConnectorClaim{Subject: hello.Subject, ServiceID: hello.ServiceID,
		SessionID: hello.SessionID, Credential: hello.Credential, Nonce: hello.Nonce, Signature: hello.Signature}
}

func NewConnectorSessionNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	return nonce, err
}
