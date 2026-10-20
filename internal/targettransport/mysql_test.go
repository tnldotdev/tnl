package targettransport

import (
	"bytes"
	"errors"
	"testing"
)

func TestMySQLEmptyPacketRequiresClientAuthResponseContext(t *testing.T) {
	packet := []byte{0, 0, 0, 4}
	if _, err := ReadMySQLPacket(bytes.NewReader(packet), MySQLMaxPacket); !errors.Is(err, ErrDatabaseTLS) {
		t.Fatal("empty server packet accepted", err)
	}
	got, err := ReadMySQLAuthResponse(bytes.NewReader(packet), MySQLMaxPacket)
	if err != nil || !bytes.Equal(got, packet) {
		t.Fatal("empty auth response lost sequence", got, err)
	}
}
