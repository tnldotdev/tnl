package tunnelv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
)

const (
	MaxVisitorSourceProofBytes     = 1536
	MaxVisitorSourceAuthorityBytes = 1024
	VisitorSourceProofTLV          = 0xe0
)

var ErrVisitorSourceProof = errors.New("visitor source proof is invalid")

// VisitorSourceAuthority delegates source attestation, never visitor permission
// or capacity. control binds one ingress process to one exact public URL run.
type VisitorSourceAuthority struct {
	PublicURLID           string `json:"public_url_id"`
	PublishRunID          string `json:"publish_run_id"`
	PublishRunNumber      uint64 `json:"publish_run_number"`
	IngressID             string `json:"ingress_id"`
	IngressRunID          string `json:"ingress_run_id"`
	IngressLeaseRevision  uint64 `json:"ingress_lease_revision"`
	VisitorPolicyRevision int64  `json:"visitor_policy_revision"`
	ValidUntil            int64  `json:"valid_until"`
	MAC                   []byte `json:"mac,omitempty"`
}

func (a VisitorSourceAuthority) ValidBinding() bool {
	return validIdentifier(a.PublicURLID) && validIdentifier(a.PublishRunID) && a.PublishRunNumber > 0 &&
		validIdentifier(a.IngressID) && validIdentifier(a.IngressRunID) && a.IngressLeaseRevision > 0 &&
		a.VisitorPolicyRevision > 0 && a.ValidUntil > 0
}

func (a VisitorSourceAuthority) SigningBytes() ([]byte, error) {
	if !a.ValidBinding() {
		return nil, ErrVisitorSourceProof
	}
	a.MAC = nil
	return json.Marshal(a)
}

func (a VisitorSourceAuthority) MarshalBinary() ([]byte, error) {
	if !a.ValidBinding() || len(a.MAC) != 32 {
		return nil, ErrVisitorSourceProof
	}
	wire, err := json.Marshal(a)
	if err != nil || len(wire) > MaxVisitorSourceAuthorityBytes {
		return nil, ErrVisitorSourceProof
	}
	return wire, nil
}

func ReadVisitorSourceAuthority(wire []byte) (VisitorSourceAuthority, error) {
	var authority VisitorSourceAuthority
	if len(wire) == 0 || len(wire) > MaxVisitorSourceAuthorityBytes {
		return authority, ErrVisitorSourceProof
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&authority) != nil || decoder.Decode(new(any)) != io.EOF {
		return VisitorSourceAuthority{}, ErrVisitorSourceProof
	}
	if _, err := authority.MarshalBinary(); err != nil {
		return VisitorSourceAuthority{}, err
	}
	return authority, nil
}

// VisitorSourceBinding supplies the exact outer stream identity and the original
// PROXY v2 endpoints. the relay cannot choose another identity or rewrite either
// endpoint without invalidating the proof.
type VisitorSourceBinding struct {
	PublicURLID      string         `json:"public_url_id"`
	PublishRunID     string         `json:"publish_run_id"`
	PublishRunNumber uint64         `json:"publish_run_number"`
	VisitorID        string         `json:"visitor_connection_id"`
	Source           netip.AddrPort `json:"source"`
	Destination      netip.AddrPort `json:"destination"`
}

func (b VisitorSourceBinding) valid() bool {
	validEndpoint := func(endpoint netip.AddrPort) bool {
		return endpoint.IsValid() && endpoint.Port() != 0 && endpoint.Addr().Zone() == "" &&
			!endpoint.Addr().IsUnspecified() && !endpoint.Addr().Is4In6()
	}
	return validIdentifier(b.PublicURLID) && validIdentifier(b.PublishRunID) && b.PublishRunNumber > 0 &&
		validIdentifier(b.VisitorID) && validEndpoint(b.Source) && validEndpoint(b.Destination)
}

// VisitorSourceProof travels once in ingress-created PROXY v2 metadata. relays
// preserve those bytes; it is independent of transport choice and capacity.
type VisitorSourceProof struct {
	Authority VisitorSourceAuthority `json:"authority"`
	Sequence  uint64                 `json:"sequence"`
	MAC       []byte                 `json:"mac,omitempty"`
}

func (p VisitorSourceProof) SigningBytes(binding VisitorSourceBinding) ([]byte, error) {
	if !binding.valid() || !p.Authority.ValidBinding() || len(p.Authority.MAC) != 32 || p.Sequence == 0 ||
		p.Authority.PublicURLID != binding.PublicURLID || p.Authority.PublishRunID != binding.PublishRunID || p.Authority.PublishRunNumber != binding.PublishRunNumber {
		return nil, ErrVisitorSourceProof
	}
	p.MAC = nil
	return json.Marshal(struct {
		Proof   VisitorSourceProof   `json:"proof"`
		Binding VisitorSourceBinding `json:"binding"`
	}{p, binding})
}

func (p VisitorSourceProof) MarshalBinary() ([]byte, error) {
	if !p.Authority.ValidBinding() || len(p.Authority.MAC) != 32 || len(p.MAC) != 32 || p.Sequence == 0 {
		return nil, ErrVisitorSourceProof
	}
	wire, err := json.Marshal(p)
	if err != nil || len(wire) > MaxVisitorSourceProofBytes {
		return nil, ErrVisitorSourceProof
	}
	return wire, nil
}

func ReadVisitorSourceProof(wire []byte) (VisitorSourceProof, error) {
	var proof VisitorSourceProof
	if len(wire) == 0 || len(wire) > MaxVisitorSourceProofBytes {
		return VisitorSourceProof{}, ErrVisitorSourceProof
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF {
		return VisitorSourceProof{}, ErrVisitorSourceProof
	}
	if _, err := proof.MarshalBinary(); err != nil {
		return VisitorSourceProof{}, err
	}
	return proof, nil
}
