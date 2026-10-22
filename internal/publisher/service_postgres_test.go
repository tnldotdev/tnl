package publisher

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestManagedPostgresTLSNegotiation(t *testing.T) {
	for _, gss := range []bool{false, true} {
		t.Run(map[bool]string{false: "SSLRequest", true: "GSS-then-SSLRequest"}[gss], func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			_ = server.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { done <- acceptPostgresTLS(server) }()
			var reply [1]byte
			if gss {
				if _, err := client.Write(managedPostgresGSS[:]); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(client, reply[:]); err != nil || reply[0] != 'N' {
					t.Fatal("GSS must be refused before offering TLS", err)
				}
			}
			if _, err := client.Write(managedPostgresSSL[:]); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(client, reply[:]); err != nil || reply[0] != 'S' {
				t.Fatal("SSLRequest must select TLS", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
