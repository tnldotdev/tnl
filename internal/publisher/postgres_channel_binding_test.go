package publisher

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestPostgresPlusChoiceReturnsActionableError(t *testing.T) {
	client, publisher := net.Pipe()
	t.Cleanup(func() { client.Close(); publisher.Close() })
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = publisher.SetDeadline(time.Now().Add(2 * time.Second))
	startup := []byte{0, 0, 0, 8, 0, 3, 0, 0}
	response := make(chan error, 1)
	go func() {
		if _, err := client.Write(startup); err != nil {
			response <- err
			return
		}
		choice := postgresChoiceTestMessage('p', postgresPlusMethod)
		if _, err := client.Write(choice); err != nil {
			response <- err
			return
		}
		var header [5]byte
		if _, err := io.ReadFull(client, header[:]); err != nil {
			response <- err
			return
		}
		if header[0] != 'E' {
			response <- errors.New("missing PostgreSQL ErrorResponse")
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint32(header[1:]))-4)
		if _, err := io.ReadFull(client, body); err != nil {
			response <- err
			return
		}
		var pgError pgproto3.ErrorResponse
		if err := pgError.Decode(body); err != nil {
			response <- err
			return
		}
		if pgError.Code != "28000" || pgError.Severity != "FATAL" ||
			!strings.Contains(pgError.Message, "channel_binding=disable") {
			response <- errors.New("PostgreSQL client error did not explain the next step")
			return
		}
		response <- nil
	}()
	reader := &postgresAuthChoiceConn{Conn: publisher}
	got := make([]byte, len(startup))
	if _, err := io.ReadFull(reader, got); err != nil || !bytes.Equal(got, startup) {
		t.Fatalf("startup = %x, %v", got, err)
	}
	if _, err := reader.Read(make([]byte, 64)); !errors.Is(err, errPostgresChannelBinding) {
		t.Fatalf("channel binding choice = %v", err)
	}
	if err := <-response; err != nil {
		t.Fatal(err)
	}
}

func TestPostgresAuthChoicePreservesOtherFrames(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"opaque fixture", []byte("startup!")},
		{"ordinary SCRAM", append(append([]byte{0, 0, 0, 8, 0, 3, 0, 0},
			postgresChoiceTestMessage('p', []byte("SCRAM-SHA-256\x00\x00\x00\x00\x03n,,"))...),
			postgresChoiceTestMessage('Q', []byte("SELECT 1\x00"))...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, publisher := net.Pipe()
			defer publisher.Close()
			go func() {
				_, _ = client.Write(test.data)
				client.Close()
			}()
			got, err := io.ReadAll(&postgresAuthChoiceConn{Conn: publisher})
			if err != nil || !bytes.Equal(got, test.data) {
				t.Fatalf("forwarded bytes = %x, %v", got, err)
			}
		})
	}
}

func postgresChoiceTestMessage(kind byte, body []byte) []byte {
	packet := make([]byte, 5+len(body))
	packet[0] = kind
	binary.BigEndian.PutUint32(packet[1:], uint32(len(body)+4))
	copy(packet[5:], body)
	return packet
}
