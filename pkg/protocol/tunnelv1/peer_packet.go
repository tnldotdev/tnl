package tunnelv1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	// peer packets fit inside a QUIC DATAGRAM even on a 1200-byte outer path.
	// a 1200-byte inner packet takes at most two bounded fragments.
	MaxPeerPacketBytes = 1200
	PeerFragmentBytes  = 1000
	PeerPacketOverhead = 17 + 32
	MaxPeerFrameBytes  = PeerFragmentBytes + PeerPacketOverhead
	// the shared outer delivery header binds a frame or stream to one exact
	// introduction and its current delivery generation. it does not authorize a target.
	PeerDeliveryHeaderBytes = 1 + 16 + 8
	PeerDeliveryTagBytes    = sha256.Size
	MaxPeerDeliveryBytes    = PeerDeliveryHeaderBytes + MaxPeerFrameBytes + PeerDeliveryTagBytes
)

var ErrPeerPacket = errors.New("peer packet is invalid")

// PeerDeliveryMode separates datagram authentication from framed stream
// authentication even when two carrier bindings accidentally share a key.
type PeerDeliveryMode byte

const (
	PeerDeliveryDatagram PeerDeliveryMode = 1
	PeerDeliveryStream   PeerDeliveryMode = 2
)

const peerDeliveryMACDomain = "tnl-peer-delivery-v1\x00"

func (mode PeerDeliveryMode) valid() bool {
	return mode == PeerDeliveryDatagram || mode == PeerDeliveryStream
}

type PeerDelivery struct {
	Pair       [16]byte
	Generation uint64
}

func (d PeerDelivery) Valid() bool { return d.Pair != [16]byte{} && d.Generation != 0 }

func (d PeerDelivery) Header() ([PeerDeliveryHeaderBytes]byte, error) {
	var b [PeerDeliveryHeaderBytes]byte
	if !d.Valid() {
		return b, ErrPeerPacket
	}
	b[0] = Version
	copy(b[1:17], d.Pair[:])
	binary.BigEndian.PutUint64(b[17:], d.Generation)
	return b, nil
}

func ParsePeerDeliveryHeader(b []byte) (PeerDelivery, error) {
	if len(b) != PeerDeliveryHeaderBytes || b[0] != Version {
		return PeerDelivery{}, ErrPeerPacket
	}
	var d PeerDelivery
	copy(d.Pair[:], b[1:17])
	d.Generation = binary.BigEndian.Uint64(b[17:])
	if !d.Valid() {
		return PeerDelivery{}, ErrPeerPacket
	}
	return d, nil
}

// Seal authenticates the version, exact pair, generation, mode,
// and entire inner frame, including the inner MAC. the pair ID is not a grant.
func (d PeerDelivery) Seal(mode PeerDeliveryMode, key [32]byte, frame []byte) ([]byte, error) {
	header, err := d.Header()
	if err != nil || !mode.valid() || key == [32]byte{} {
		return nil, ErrPeerPacket
	}
	if _, err := ParsePeerPacket(frame); err != nil {
		return nil, err
	}
	b := make([]byte, 0, len(header)+len(frame)+PeerDeliveryTagBytes)
	b = append(b, header[:]...)
	b = append(b, frame...)
	tag := peerDeliveryTag(mode, key, b)
	return append(b, tag[:]...), nil
}

func peerDeliveryTag(mode PeerDeliveryMode, key [32]byte, authenticated []byte) [PeerDeliveryTagBytes]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte(peerDeliveryMACDomain))
	_, _ = mac.Write([]byte{byte(mode)})
	_, _ = mac.Write(authenticated)
	var tag [PeerDeliveryTagBytes]byte
	copy(tag[:], mac.Sum(nil))
	return tag
}

// OpenPeerDelivery rejects unauthenticated headers before returning the frame.
func OpenPeerDelivery(b []byte, mode PeerDeliveryMode, key [32]byte) (PeerDelivery, []byte, error) {
	if len(b) <= PeerDeliveryHeaderBytes+PeerDeliveryTagBytes+PeerPacketOverhead || len(b) > MaxPeerDeliveryBytes ||
		!mode.valid() || key == [32]byte{} {
		return PeerDelivery{}, nil, ErrPeerPacket
	}
	d, err := ParsePeerDeliveryHeader(b[:PeerDeliveryHeaderBytes])
	if err != nil {
		return PeerDelivery{}, nil, err
	}
	frameEnd := len(b) - PeerDeliveryTagBytes
	if _, err := ParsePeerPacket(b[PeerDeliveryHeaderBytes:frameEnd]); err != nil {
		return PeerDelivery{}, nil, err
	}
	tag := peerDeliveryTag(mode, key, b[:frameEnd])
	if !hmac.Equal(tag[:], b[frameEnd:]) {
		return PeerDelivery{}, nil, ErrPeerPacket
	}
	return d, b[PeerDeliveryHeaderBytes:frameEnd], nil
}

// WritePeerDeliveryFrame and ReadPeerDeliveryFrame bound reliable carrier
// allocations before inspecting the authenticated v1 envelope.
func WritePeerDeliveryFrame(w io.Writer, b []byte, mode PeerDeliveryMode, key [32]byte) error {
	if _, _, err := OpenPeerDelivery(b, mode, key); err != nil {
		return err
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(b)))
	for _, part := range [][]byte{header[:], b} {
		if n, err := w.Write(part); err != nil {
			return err
		} else if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func ReadPeerDeliveryFrame(r io.Reader, mode PeerDeliveryMode, key [32]byte) (PeerDelivery, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return PeerDelivery{}, nil, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n <= PeerDeliveryHeaderBytes+PeerDeliveryTagBytes+PeerPacketOverhead || n > MaxPeerDeliveryBytes {
		return PeerDelivery{}, nil, ErrPeerPacket
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return PeerDelivery{}, nil, err
	}
	return OpenPeerDelivery(b, mode, key)
}

type PeerPacketKind uint8

const (
	PeerData PeerPacketKind = iota + 1
	PeerProbe
	PeerProbeReply
)

// PeerPacket carries encrypted inner QUIC bytes or a path challenge. the MAC
// binds the pair's introduction key, direction, path, sequence, and fragments.
// receiving this shape alone grants neither target access nor a direct path.
type PeerPacket struct {
	Kind     PeerPacketKind
	Sender   uint8
	Path     uint8
	Sequence uint64
	Fragment uint8
	Total    uint16
	Payload  []byte
	MAC      [32]byte
}

func (p PeerPacket) Validate() error {
	if p.Sender > 1 || p.Path > 2 || p.Sequence == 0 || len(p.Payload) == 0 || len(p.Payload) > PeerFragmentBytes {
		return ErrPeerPacket
	}
	switch p.Kind {
	case PeerData:
		if p.Total == 0 || p.Total > MaxPeerPacketBytes || int(p.Fragment)*PeerFragmentBytes >= int(p.Total) || len(p.Payload) != min(PeerFragmentBytes, int(p.Total)-int(p.Fragment)*PeerFragmentBytes) {
			return ErrPeerPacket
		}
	case PeerProbe, PeerProbeReply:
		if p.Total != 16 || p.Fragment != 0 || len(p.Payload) != 16 {
			return ErrPeerPacket
		}
	default:
		return ErrPeerPacket
	}
	return nil
}

// AuthenticatedBytes is the canonical MAC input, excluding the MAC itself.
func (p PeerPacket) AuthenticatedBytes() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 17+len(p.Payload))
	b[0], b[1], b[2], b[3], b[4] = Version, byte(p.Kind), p.Sender, p.Path, p.Fragment
	binary.BigEndian.PutUint64(b[5:13], p.Sequence)
	binary.BigEndian.PutUint16(b[13:15], p.Total)
	binary.BigEndian.PutUint16(b[15:17], uint16(len(p.Payload)))
	copy(b[17:], p.Payload)
	return b, nil
}

func (p PeerPacket) MarshalBinary() ([]byte, error) {
	b, err := p.AuthenticatedBytes()
	if err != nil {
		return nil, err
	}
	return append(b, p.MAC[:]...), nil
}

func ParsePeerPacket(b []byte) (PeerPacket, error) {
	if len(b) <= PeerPacketOverhead || len(b) > MaxPeerFrameBytes || b[0] != Version || int(binary.BigEndian.Uint16(b[15:17])) != len(b)-PeerPacketOverhead {
		return PeerPacket{}, ErrPeerPacket
	}
	p := PeerPacket{Kind: PeerPacketKind(b[1]), Sender: b[2], Path: b[3], Fragment: b[4], Sequence: binary.BigEndian.Uint64(b[5:13]), Total: binary.BigEndian.Uint16(b[13:15]), Payload: b[17 : len(b)-32]}
	copy(p.MAC[:], b[len(b)-32:])
	if err := p.Validate(); err != nil {
		return PeerPacket{}, err
	}
	return p, nil
}

// WritePeerFrame and ReadPeerFrame preserve packet boundaries on a reliable
// carrier. readers reject an oversized length before allocating its payload.
func WritePeerFrame(w io.Writer, b []byte) error {
	if _, err := ParsePeerPacket(b); err != nil {
		return err
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(b)))
	for _, part := range [][]byte{header[:], b} {
		if n, err := w.Write(part); err != nil {
			return err
		} else if n != len(part) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func ReadPeerFrame(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[:]))
	if n <= PeerPacketOverhead || n > MaxPeerFrameBytes {
		return nil, ErrPeerPacket
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	if _, err := ParsePeerPacket(b); err != nil {
		return nil, err
	}
	return b, nil
}
