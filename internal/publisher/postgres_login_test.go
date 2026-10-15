package publisher

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func pgWire(kind byte, body string) []byte {
	b := make([]byte, 5+len(body))
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:], uint32(4+len(body)))
	copy(b[5:], body)
	return b
}

func TestPostgresPlusRefusalDoesNotForwardProof(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	received := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		startup := make([]byte, 8)
		if _, err := io.ReadFull(c, startup); err != nil {
			received <- startup
			return
		}
		_, _ = c.Write(pgWire('R', "\x00\x00\x00\x0aSCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00\x00"))
		b, _ := io.ReadAll(c)
		received <- b
	}()
	certificate := publicURLTestCertificate(t, "route.example")
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", ServiceProtocol: controlv1.Postgres, PublicPort: 5432, Target: l.Addr().String(), Certificate: certificate})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	visitor := realDatabaseVisitor(t, route, 5432)
	_, _ = visitor.Write(postgresSSLRequest[:])
	readDatabaseByte(t, visitor, 'S')
	secured := tls.Client(visitor, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)})
	if err := secured.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, _ = secured.Write([]byte{0, 0, 0, 8, 0, 3, 0, 0})
	challenge := pgWire('R', "\x00\x00\x00\x0aSCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00\x00")
	got := make([]byte, len(challenge))
	if _, err := io.ReadFull(secured, got); err != nil {
		t.Fatal(err)
	}
	if _, err := secured.Write(pgWire('p', "SCRAM-SHA-256-PLUS\x00\x00\x00\x00\x0bsecret-proof")); err != nil {
		t.Fatal(err)
	}
	problem, err := io.ReadAll(secured)
	if err != nil || len(problem) < 5 || problem[0] != 'E' || !bytes.Contains(problem, []byte("channel_binding=disable")) || bytes.Contains(problem, []byte("secret-proof")) {
		t.Fatalf("refusal=%q, %v", problem, err)
	}
	if b := awaitPublisherTest(t, received); len(b) != 0 {
		t.Fatalf("PLUS header or proof reached target: %q", b)
	}
}

func TestPostgresLoginGuardRetainsOrdinaryAuthAndHalfClose(t *testing.T) {
	for _, allowPlus := range []bool{false, true} {
		left, right := net.Pipe()
		_ = left.SetDeadline(time.Now().Add(5 * time.Second))
		_ = right.SetDeadline(time.Now().Add(5 * time.Second))
		startup := []byte{0, 0, 0, 8, 0, 3, 0, 0}
		method := "SCRAM-SHA-256\x00"
		if allowPlus {
			method = "SCRAM-SHA-256-PLUS\x00"
		}
		want := append(startup, pgWire('p', method+"\x00\x00\x00\x00")...)
		done := make(chan []byte, 1)
		go func() {
			b, _ := io.ReadAll(&postgresLoginConn{Conn: right, allowPlus: allowPlus})
			done <- b
			_ = right.Close()
		}()
		_, _ = left.Write(want)
		_ = left.Close()
		if got := awaitPublisherTest(t, done); !bytes.Equal(got, want) {
			t.Fatalf("ordinary auth changed: %x", got)
		}
	}
}
