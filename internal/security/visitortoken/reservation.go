package visitortoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/netip"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// SignReservation binds an ingress-owned slot and trusted source address to
// control's allocation key. a relay carries the proof but cannot change it.
func SignReservation(key []byte, reservation *tunnelv1.StreamReservation, source netip.Addr) error {
	if reservation == nil || len(key) != sha256.Size || !source.IsValid() || source.Zone() != "" {
		return ErrBinding
	}
	unsigned := *reservation
	unsigned.SourceIP, unsigned.Proof = "", ""
	if unsigned.Validate() != nil {
		return ErrBinding
	}
	unsigned.SourceIP = source.Unmap().String()
	proof, err := reservationMAC(key, unsigned)
	if err != nil {
		return err
	}
	reservation.SourceIP, reservation.Proof = unsigned.SourceIP, base64.RawURLEncoding.EncodeToString(proof)
	return nil
}

func VerifyReservation(key []byte, reservation tunnelv1.StreamReservation) error {
	if len(key) != sha256.Size || reservation.Validate() != nil || reservation.SourceIP == "" || reservation.Proof == "" {
		return ErrBinding
	}
	provided, err := base64.RawURLEncoding.Strict().DecodeString(reservation.Proof)
	if err != nil || len(provided) != sha256.Size {
		return ErrBinding
	}
	reservation.Proof = ""
	expected, err := reservationMAC(key, reservation)
	if err != nil || subtle.ConstantTimeCompare(provided, expected) != 1 {
		return ErrBinding
	}
	return nil
}

func reservationMAC(key []byte, reservation tunnelv1.StreamReservation) ([]byte, error) {
	payload, err := json.Marshal(reservation)
	if err != nil {
		return nil, ErrBinding
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("tnl/stream-reservation/v1\x00"))
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}
