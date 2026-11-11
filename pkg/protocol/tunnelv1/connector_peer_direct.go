package tunnelv1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

const (
	ConnectorPeerDirectHeaderBytes = 17
	ConnectorPeerDirectTagBytes    = sha256.Size
	MaxConnectorPeerDirectBytes    = ConnectorPeerDirectHeaderBytes + MaxPeerFrameBytes + ConnectorPeerDirectTagBytes
)

// ConnectorPeerDirect binds packet delivery to one ICE attempt and network
// binding. the key comes from both endpoints' authenticated signaling transcript;
// it is distinct from the retained endpoint key and every relay envelope key.
type ConnectorPeerDirect struct {
	Generation uint64
	Attempt    uint64
}

func (d ConnectorPeerDirect) Seal(frame []byte, key [32]byte) ([]byte, error) {
	inner, err := ParsePeerPacket(frame)
	if err != nil || key == [32]byte{} || d.Generation == 0 || d.Attempt == 0 || inner.BindingGeneration != d.Generation || inner.Path != 2 {
		return nil, ErrPeerPacket
	}
	packet := make([]byte, ConnectorPeerDirectHeaderBytes, ConnectorPeerDirectHeaderBytes+len(frame)+ConnectorPeerDirectTagBytes)
	packet[0] = Version
	binary.BigEndian.PutUint64(packet[1:9], d.Generation)
	binary.BigEndian.PutUint64(packet[9:17], d.Attempt)
	packet = append(packet, frame...)
	return connectorPeerDirectMAC(key, packet).Sum(packet), nil
}

func OpenConnectorPeerDirect(packet []byte, key [32]byte) (ConnectorPeerDirect, []byte, error) {
	if len(packet) <= ConnectorPeerDirectHeaderBytes+ConnectorPeerDirectTagBytes+PeerPacketOverhead || len(packet) > MaxConnectorPeerDirectBytes || packet[0] != Version || key == [32]byte{} {
		return ConnectorPeerDirect{}, nil, ErrPeerPacket
	}
	end := len(packet) - ConnectorPeerDirectTagBytes
	if !hmac.Equal(connectorPeerDirectMAC(key, packet[:end]).Sum(nil), packet[end:]) {
		return ConnectorPeerDirect{}, nil, ErrPeerPacket
	}
	d := ConnectorPeerDirect{Generation: binary.BigEndian.Uint64(packet[1:9]), Attempt: binary.BigEndian.Uint64(packet[9:17])}
	frame := packet[ConnectorPeerDirectHeaderBytes:end]
	inner, err := ParsePeerPacket(frame)
	if err != nil || d.Generation == 0 || d.Attempt == 0 || inner.BindingGeneration != d.Generation || inner.Path != 2 {
		return ConnectorPeerDirect{}, nil, ErrPeerPacket
	}
	return d, frame, nil
}

func connectorPeerDirectMAC(key [32]byte, packet []byte) hash.Hash {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("tnl connector direct packet v1\x00"))
	_, _ = mac.Write(packet)
	return mac
}
