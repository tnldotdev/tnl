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

const MaxPrivateHeaderBytes = 2 << 10

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
}

func (h PrivateConnectorSessionHello) Validate() error {
	if h.ProtocolVersion != Version || h.Kind != "private_connector_session" ||
		!opaqueid.Valid(h.PrivateServiceID, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(h.SessionID, opaqueid.PrivateConnectorSessionPrefix) ||
		!validCredential(h.Credential) || len(h.Credential) > 512 {
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

// PrivateVisitorEntry starts each visitor stream within an authenticated mux
// session. ingress checks this exact service/run and consumes one fresh ticket
// against the session identity and trusted source before forwarding any bytes.
// no client-supplied IP or untrusted SNI selects a private service.
type PrivateVisitorEntry struct {
	ProtocolVersion  uint32     `json:"protocol_version"`
	Kind             StreamKind `json:"kind"`
	PrivateServiceID string     `json:"private_service_id"`
	PrivateRunID     string     `json:"private_run_id"`
	RunNumber        uint64     `json:"run_number"`
	Ticket           string     `json:"ticket"`
	Nonce            []byte     `json:"nonce"`
}

func (e PrivateVisitorEntry) Validate() error {
	if e.ProtocolVersion != Version || e.Kind != PrivateVisitorStream ||
		!opaqueid.Valid(e.PrivateServiceID, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(e.PrivateRunID, opaqueid.PrivateRunPrefix) ||
		e.RunNumber == 0 || !validCredential(e.Ticket) || len(e.Ticket) > 512 || len(e.Nonce) != 32 {
		return errors.New("tunnelv1: invalid private visitor entry")
	}
	return nil
}

// PrivateVisitorAccepted carries ingress's trusted, claimed stream identity
// back to the connector before inner TLS. the connector compares session and
// source with the control API ticket response. the publisher receives the
// same identity in PrivateStreamHeader and signs it before application bytes.
type PrivateVisitorAccepted struct {
	ProtocolVersion     uint32 `json:"protocol_version"`
	Kind                string `json:"kind"`
	ConnectorSessionID  string `json:"connector_session_id"`
	IdentityID          string `json:"identity_id"`
	SourceIP            string `json:"source_ip"`
	VisitorConnectionID string `json:"visitor_connection_id"`
}

func (a PrivateVisitorAccepted) Validate() error {
	if a.ProtocolVersion != Version || a.Kind != "private_visitor_accepted" ||
		!opaqueid.Valid(a.ConnectorSessionID, opaqueid.PrivateConnectorSessionPrefix) ||
		!opaqueid.Valid(a.IdentityID, opaqueid.IdentityPrefix) || !validPrivateSourceIP(a.SourceIP) ||
		!opaqueid.Valid(a.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) {
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
// compare its IDs, assignment revision and ticket digest with the claimed run;
// never permit a public URL connection reference on this stream.
type PrivateStreamHeader struct {
	ProtocolVersion              uint32     `json:"protocol_version"`
	Kind                         StreamKind `json:"kind"`
	PrivateServiceID             string     `json:"private_service_id"`
	PrivateRunID                 string     `json:"private_run_id"`
	ConnectorSessionID           string     `json:"connector_session_id"`
	IdentityID                   string     `json:"identity_id"`
	SourceIP                     string     `json:"source_ip"`
	RunNumber                    uint64     `json:"run_number"`
	VisitorConnectionID          string     `json:"visitor_connection_id"`
	PublisherConnectionID        string     `json:"publisher_connection_id"`
	ConnectionAssignmentRevision uint64     `json:"connection_assignment_revision"`
	TicketDigest                 []byte     `json:"ticket_digest"`
	Nonce                        []byte     `json:"nonce"`
	ExpiresAt                    time.Time  `json:"expires_at"`
}

func (h PrivateStreamHeader) Validate() error {
	return h.validate(PrivateVisitorStream)
}

func (h PrivateStreamHeader) validate(kind StreamKind) error {
	if h.ProtocolVersion != Version || h.Kind != kind ||
		!opaqueid.Valid(h.PrivateServiceID, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(h.PrivateRunID, opaqueid.PrivateRunPrefix) || h.RunNumber == 0 ||
		!opaqueid.Valid(h.ConnectorSessionID, opaqueid.PrivateConnectorSessionPrefix) ||
		!opaqueid.Valid(h.IdentityID, opaqueid.IdentityPrefix) || !validPrivateSourceIP(h.SourceIP) ||
		!opaqueid.Valid(h.VisitorConnectionID, opaqueid.VisitorConnectionPrefix) ||
		!opaqueid.Valid(h.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) ||
		h.ConnectionAssignmentRevision == 0 || len(h.TicketDigest) != sha256.Size || len(h.Nonce) != 32 || h.ExpiresAt.IsZero() {
		return errors.New("tunnelv1: invalid private stream header")
	}
	return nil
}

func validPrivateSourceIP(value string) bool {
	addr, err := netip.ParseAddr(value)
	return err == nil && addr.IsValid() && addr.Zone() == "" && addr.String() == value
}

// PrivateForwardingHeader carries the current relay lease along with the
// already claimed service/run/ticket binding. it never accepts public URL IDs.
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
	if h.ConnectionSlot > 1 || !validPrivateIdentifier(h.RelayServiceID) || !validPrivateIdentifier(h.RelayID) ||
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

// PrivateStreamProof authenticates the publisher before application bytes,
// inside end-to-end TLS 1.3. the visitor pins the publisher's per-run TLS
// certificate public key to control's stream_public_key and verifies this
// signature with that same key. neither ingress nor relay has the run key.
type PrivateStreamProof struct {
	Signature []byte `json:"signature"`
}

func (p PrivateStreamProof) Validate() error {
	if len(p.Signature) != ed25519.SignatureSize {
		return errors.New("tunnelv1: invalid private stream proof")
	}
	return nil
}

func WritePrivateStreamProof(w io.Writer, p PrivateStreamProof) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return writeJSONFrame(w, p, MaxPrivateHeaderBytes)
}

func ReadPrivateStreamProof(r io.Reader) (PrivateStreamProof, error) {
	var p PrivateStreamProof
	if err := readJSONFrame(r, &p, MaxPrivateHeaderBytes); err != nil {
		return PrivateStreamProof{}, err
	}
	if err := p.Validate(); err != nil {
		return PrivateStreamProof{}, err
	}
	return p, nil
}

// PrivateChallenge binds the publisher's proof to the one-use ticket digest
// and ingress's claimed session/source/visitor identity. the publisher receives
// the digest, not the raw ticket. neither endpoint takes trusted fields from a
// visitor frame.
func PrivateChallenge(e PrivateVisitorEntry, accepted PrivateVisitorAccepted) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if err := accepted.Validate(); err != nil {
		return nil, err
	}
	ticketDigest := sha256.Sum256([]byte(e.Ticket))
	return privateChallenge(e.PrivateServiceID, e.PrivateRunID, e.RunNumber, ticketDigest[:], e.Nonce, accepted), nil
}

// PrivateChallengeFromHeader lets the publisher sign the same challenge using
// only claimed ingress state. its trusted header contains the ticket digest,
// session, identity, source and visitor connection ID, never the raw ticket.
func PrivateChallengeFromHeader(header PrivateStreamHeader) ([]byte, error) {
	if err := header.Validate(); err != nil {
		return nil, err
	}
	accepted := PrivateVisitorAccepted{
		ProtocolVersion: Version, Kind: "private_visitor_accepted",
		ConnectorSessionID: header.ConnectorSessionID, IdentityID: header.IdentityID,
		SourceIP: header.SourceIP, VisitorConnectionID: header.VisitorConnectionID,
	}
	return privateChallenge(header.PrivateServiceID, header.PrivateRunID, header.RunNumber,
		header.TicketDigest, header.Nonce, accepted), nil
}

func privateChallenge(serviceID, runID string, runNumber uint64, ticketDigest, nonce []byte, accepted PrivateVisitorAccepted) []byte {
	h := sha256.New()
	h.Write([]byte("tnl/private-service/visitor-proof/v1\x00"))
	for _, field := range [][]byte{
		[]byte(serviceID), []byte(runID), ticketDigest, nonce,
		[]byte(accepted.ConnectorSessionID), []byte(accepted.IdentityID),
		[]byte(accepted.SourceIP), []byte(accepted.VisitorConnectionID),
	} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		h.Write(length[:])
		h.Write(field)
	}
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], runNumber)
	h.Write(number[:])
	return h.Sum(nil)
}

func NewPrivateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	return nonce, err
}

func VerifyPrivateStreamProof(publicKey ed25519.PublicKey, entry PrivateVisitorEntry, accepted PrivateVisitorAccepted, proof PrivateStreamProof) bool {
	challenge, err := PrivateChallenge(entry, accepted)
	return err == nil && proof.Validate() == nil && ed25519.Verify(publicKey, challenge, proof.Signature)
}
