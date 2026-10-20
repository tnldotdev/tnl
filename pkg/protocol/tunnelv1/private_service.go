package tunnelv1

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// private forwarding includes up to three configured 256-byte process IDs,
// each of which may expand sixfold in JSON, plus fixed opaque IDs and metadata.
const MaxPrivateHeaderBytes = 8 << 10

func validPrivateIdentifier(value string) bool { return validIdentifier(value) && len(value) <= 128 }

// PrivateConnectorSessionHello authenticates one TLS-protected infrastructure
// mux session. ingress binds the claimed session to its observed source IP;
// this credential never admits a visitor stream by itself.
type PrivateConnectorSessionHello struct {
	ProtocolVersion  uint32 `json:"protocol_version"`
	Kind             string `json:"kind"`
	PrivateServiceID string `json:"private_service_id"`
	SessionID        string `json:"connector_session_id"`
	Credential       string `json:"session_credential"`
	DeviceID         string `json:"device_id"`
	IdentityID       string `json:"identity_id"`
	Nonce            []byte `json:"nonce"`
	Signature        []byte `json:"signature"`
}

func (h PrivateConnectorSessionHello) Validate() error {
	if h.ProtocolVersion != Version || h.Kind != "private_connector_session" ||
		!opaqueid.Valid(h.PrivateServiceID, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(h.SessionID, opaqueid.PrivateConnectorSessionPrefix) ||
		!validCredential(h.Credential) || len(h.Credential) > 512 ||
		!validPrivateIdentifier(h.DeviceID) || !opaqueid.Valid(h.IdentityID, opaqueid.IdentityPrefix) ||
		len(h.Nonce) != 32 || len(h.Signature) != ed25519.SignatureSize {
		return errors.New("tunnelv1: invalid private connector session hello")
	}
	return nil
}

func WritePrivateConnectorSessionHello(w io.Writer, h PrivateConnectorSessionHello) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, h, MaxPrivateHeaderBytes)
}

func ReadPrivateConnectorSessionHello(r io.Reader) (PrivateConnectorSessionHello, error) {
	var h PrivateConnectorSessionHello
	if err := readJSONFrame(r, &h, MaxPrivateHeaderBytes); err != nil {
		return PrivateConnectorSessionHello{}, err
	}
	if err := h.Validate(); err != nil {
		return PrivateConnectorSessionHello{}, err
	}
	return h, nil
}

// PrivateConnectorSessionAccepted is ingress-authenticated session state. the
// observed source comes from ingress's socket or verified PROXY metadata.
type PrivateConnectorSessionAccepted struct {
	ProtocolVersion  uint32    `json:"protocol_version"`
	Kind             string    `json:"kind"`
	PrivateServiceID string    `json:"private_service_id"`
	SessionID        string    `json:"connector_session_id"`
	DeviceID         string    `json:"device_id"`
	IdentityID       string    `json:"identity_id"`
	SourceIP         string    `json:"source_ip"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (a PrivateConnectorSessionAccepted) Validate() error {
	if a.ProtocolVersion != Version || a.Kind != "private_connector_session_accepted" ||
		!opaqueid.Valid(a.PrivateServiceID, opaqueid.PrivateServicePrefix) || !opaqueid.Valid(a.SessionID, opaqueid.PrivateConnectorSessionPrefix) ||
		!validPrivateIdentifier(a.DeviceID) || !opaqueid.Valid(a.IdentityID, opaqueid.IdentityPrefix) || !validPrivateSourceIP(a.SourceIP) || a.ExpiresAt.IsZero() {
		return errors.New("tunnelv1: invalid private connector session acceptance")
	}
	return nil
}

func WritePrivateConnectorSessionAccepted(w io.Writer, a PrivateConnectorSessionAccepted) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, a, MaxPrivateHeaderBytes)
}

func ReadPrivateConnectorSessionAccepted(r io.Reader) (PrivateConnectorSessionAccepted, error) {
	var a PrivateConnectorSessionAccepted
	if err := readJSONFrame(r, &a, MaxPrivateHeaderBytes); err != nil {
		return a, err
	}
	return a, a.Validate()
}

// PrivateVisitorEntry starts each visitor stream within an authenticated mux
// session. ingress authorizes this exact service/run against the enrolled
// session identity and trusted source before forwarding any bytes.
// no client-supplied IP or untrusted SNI selects a private service.
type PrivateVisitorEntry struct {
	TraceContext     TraceContext `json:"trace_context,omitzero"`
	ProtocolVersion  uint32       `json:"protocol_version"`
	Kind             StreamKind   `json:"kind"`
	PrivateServiceID string       `json:"private_service_id"`
	PrivateRunID     string       `json:"private_run_id"`
	RunNumber        uint64       `json:"run_number"`
}

func (e PrivateVisitorEntry) Validate() error {
	if err := e.TraceContext.Validate(); err != nil {
		return err
	}
	if e.ProtocolVersion != Version || e.Kind != PrivateVisitorStream ||
		!opaqueid.Valid(e.PrivateServiceID, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(e.PrivateRunID, opaqueid.PrivateRunPrefix) ||
		e.RunNumber == 0 {
		return errors.New("tunnelv1: invalid private visitor entry")
	}
	return nil
}

// PrivateVisitorAccepted carries ingress's trusted, claimed stream identity
// back to the connector before inner TLS. the connector compares session and
// source with the authenticated session. the publisher receives the
// same admitted identity in PrivateStreamHeader and rechecks it with control.
type PrivateVisitorAccepted struct {
	ProtocolVersion              uint32 `json:"protocol_version"`
	Kind                         string `json:"kind"`
	ConnectorSessionID           string `json:"connector_session_id"`
	IdentityID                   string `json:"identity_id"`
	SourceIP                     string `json:"source_ip"`
	VisitorConnectionID          string `json:"visitor_connection_id"`
	DeviceID                     string `json:"device_id"`
	GrantRevision                uint64 `json:"grant_revision"`
	PublisherConnectionID        string `json:"publisher_connection_id"`
	ConnectionAssignmentRevision uint64 `json:"connection_assignment_revision"`
}

func (a PrivateVisitorAccepted) Validate() error {
	if a.ProtocolVersion != Version || a.Kind != "private_visitor_accepted" ||
		!opaqueid.Valid(a.ConnectorSessionID, opaqueid.PrivateConnectorSessionPrefix) ||
		!opaqueid.Valid(a.IdentityID, opaqueid.IdentityPrefix) || !validPrivateSourceIP(a.SourceIP) ||
		!opaqueid.Valid(a.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) || !validPrivateIdentifier(a.DeviceID) || a.GrantRevision == 0 ||
		!opaqueid.Valid(a.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) || a.ConnectionAssignmentRevision == 0 {
		return errors.New("tunnelv1: invalid private visitor acceptance")
	}
	return nil
}

func WritePrivateVisitorAccepted(w io.Writer, a PrivateVisitorAccepted) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, a, MaxPrivateHeaderBytes)
}

func ReadPrivateVisitorAccepted(r io.Reader) (PrivateVisitorAccepted, error) {
	var a PrivateVisitorAccepted
	if err := readJSONFrame(r, &a, MaxPrivateHeaderBytes); err != nil {
		return PrivateVisitorAccepted{}, err
	}
	if err := a.Validate(); err != nil {
		return PrivateVisitorAccepted{}, err
	}
	return a, nil
}

func WritePrivateVisitorEntry(w io.Writer, e PrivateVisitorEntry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, e, MaxPrivateHeaderBytes)
}

func ReadPrivateVisitorEntry(r io.Reader) (PrivateVisitorEntry, error) {
	var e PrivateVisitorEntry
	if err := readJSONFrame(r, &e, MaxPrivateHeaderBytes); err != nil {
		return PrivateVisitorEntry{}, err
	}
	if err := e.Validate(); err != nil {
		return PrivateVisitorEntry{}, err
	}
	return e, nil
}

// PrivateStreamHeader is trusted ingress state forwarded through a relay.
// compare its IDs, assignment and grant revisions with the claimed run;
// never permit a public URL connection reference on this stream.
type PrivateStreamHeader struct {
	TraceContext                 TraceContext        `json:"trace_context,omitzero"`
	ProtocolVersion              uint32              `json:"protocol_version"`
	Kind                         StreamKind          `json:"kind"`
	PrivateServiceID             string              `json:"private_service_id"`
	PrivateRunID                 string              `json:"private_run_id"`
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
	SessionID     string `json:"session_id"`
	IdentityID    string `json:"identity_id"`
	DeviceID      string `json:"device_id"`
	GrantRevision uint64 `json:"grant_revision"`
}

type DirectAdmission struct {
	IngressID            string `json:"ingress_id"`
	IngressRunID         string `json:"ingress_run_id"`
	IngressLeaseRevision uint64 `json:"ingress_lease_revision"`
	DestinationPort      uint16 `json:"destination_port"`
}

func (a ConnectorAdmission) valid() bool {
	return opaqueid.Valid(a.SessionID, opaqueid.PrivateConnectorSessionPrefix) &&
		opaqueid.Valid(a.IdentityID, opaqueid.IdentityPrefix) && validPrivateIdentifier(a.DeviceID) && a.GrantRevision > 0
}

func (a DirectAdmission) valid() bool {
	return validIdentifier(a.IngressID) && opaqueid.Valid(a.IngressRunID, opaqueid.IngressRunPrefix) && a.IngressLeaseRevision > 0 && a.DestinationPort >= 1024
}

func (h PrivateStreamHeader) Validate() error {
	return h.validate(PrivateVisitorStream)
}

func (h PrivateStreamHeader) validate(kind StreamKind) error {
	if err := h.TraceContext.Validate(); err != nil {
		return err
	}
	if h.ProtocolVersion != Version || h.Kind != kind ||
		!opaqueid.Valid(h.PrivateServiceID, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(h.PrivateRunID, opaqueid.PrivateRunPrefix) || h.RunNumber == 0 ||
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

// PrivateForwardingHeader carries the current relay lease along with the
// already authorized service/run/device binding. it never accepts public URL IDs.
type PrivateForwardingHeader struct {
	PrivateStreamHeader
	ConnectionSlot     uint8     `json:"connection_slot"`
	RelayServiceID     string    `json:"relay_service_id"`
	RelayID            string    `json:"relay_id"`
	RelayRunID         string    `json:"relay_run_id"`
	RelayLeaseRevision uint64    `json:"relay_lease_revision"`
	LeaseExpiresAt     time.Time `json:"lease_expires_at"`
}

func (h PrivateForwardingHeader) Validate() error {
	if err := h.PrivateStreamHeader.validate(PrivateForwardingStream); err != nil {
		return err
	}
	if h.ConnectionSlot > 1 || !validIdentifier(h.RelayServiceID) || !validIdentifier(h.RelayID) ||
		!opaqueid.Valid(h.RelayRunID, opaqueid.RelayRunPrefix) || h.RelayLeaseRevision == 0 || h.LeaseExpiresAt.IsZero() {
		return errors.New("tunnelv1: invalid private forwarding header")
	}
	return nil
}

func WritePrivateForwardingHeader(w io.Writer, h PrivateForwardingHeader) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, h, MaxPrivateHeaderBytes)
}

func ReadPrivateForwardingHeader(r io.Reader) (PrivateForwardingHeader, error) {
	var h PrivateForwardingHeader
	if err := readJSONFrame(r, &h, MaxPrivateHeaderBytes); err != nil {
		return PrivateForwardingHeader{}, err
	}
	if err := h.Validate(); err != nil {
		return PrivateForwardingHeader{}, err
	}
	return h, nil
}

func WritePrivateStreamHeader(w io.Writer, h PrivateStreamHeader) error {
	if err := h.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, h, MaxPrivateHeaderBytes)
}

func ReadPrivateStreamHeader(r io.Reader) (PrivateStreamHeader, error) {
	var h PrivateStreamHeader
	if err := readJSONFrame(r, &h, MaxPrivateHeaderBytes); err != nil {
		return PrivateStreamHeader{}, err
	}
	if err := h.Validate(); err != nil {
		return PrivateStreamHeader{}, err
	}
	return h, nil
}

// PrivateConnectorHelloDigest proves possession of the enrolled device key for
// the exact short-lived assignment. control consumes that assignment once;
// ingress supplies the observed source, never the connector.
func PrivateConnectorHelloDigest(hello PrivateConnectorSessionHello) ([]byte, error) {
	unsigned := hello
	unsigned.Signature = make([]byte, ed25519.SignatureSize)
	if err := unsigned.Validate(); err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("tnl/private-connector-session/v1\x00"))
	for _, field := range [][]byte{[]byte(hello.PrivateServiceID), []byte(hello.SessionID), []byte(hello.Credential), []byte(hello.DeviceID), []byte(hello.IdentityID), hello.Nonce} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		h.Write(length[:])
		h.Write(field)
	}
	return h.Sum(nil), nil
}

func NewConnectorSessionNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	return nonce, err
}
