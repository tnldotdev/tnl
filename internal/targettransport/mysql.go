package targettransport

import (
	"encoding/binary"
	"errors"
	"io"
)

var ErrDatabaseTLS = errors.New("verified native database TLS negotiation failed")
var PostgresSSLRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 47}

const MySQLClientSSL = 1 << 11
const MySQLClientProtocol41 = 1 << 9
const MySQLMaxPacket = 1 << 20

func MySQLSSLRequest(greeting []byte) ([]byte, error) {
	if len(greeting) < 5 || greeting[4] != 10 {
		return nil, ErrDatabaseTLS
	}
	version := 5
	for version < len(greeting) && greeting[version] != 0 {
		version++
	}
	capabilities := version + 1 + 4 + 8 + 1
	if version == len(greeting) || len(greeting) < capabilities+2+1+2+2+1+10 {
		return nil, ErrDatabaseTLS
	}
	flags := uint32(binary.LittleEndian.Uint16(greeting[capabilities:])) | uint32(binary.LittleEndian.Uint16(greeting[capabilities+5:]))<<16
	if greeting[3] != 0 || flags&MySQLClientSSL == 0 || flags&MySQLClientProtocol41 == 0 {
		return nil, ErrDatabaseTLS
	}
	packet := make([]byte, 36)
	packet[0], packet[3] = 32, 1
	binary.LittleEndian.PutUint32(packet[4:8], flags)
	binary.LittleEndian.PutUint32(packet[8:12], MySQLMaxPacket)
	packet[12] = greeting[capabilities+2]
	return packet, nil
}

func ReadMySQLPacket(source io.Reader, limit int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(source, header[:]); err != nil {
		return nil, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length < 1 || length > limit {
		return nil, ErrDatabaseTLS
	}
	packet := make([]byte, 4+length)
	copy(packet, header[:])
	if _, err := io.ReadFull(source, packet[4:]); err != nil {
		clear(packet)
		return nil, err
	}
	return packet, nil
}
