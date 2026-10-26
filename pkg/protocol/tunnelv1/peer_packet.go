package tunnelv1

import (
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
)

var ErrPeerPacket = errors.New("peer packet is invalid")

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
