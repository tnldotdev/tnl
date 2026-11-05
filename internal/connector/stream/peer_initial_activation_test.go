package stream

import (
	"bytes"
	"io"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorInitialActivationRetriesKeepOperationAndFreshHelloSeparate(t *testing.T) {
	for _, transport := range []string{"quic", "tls_tcp"} {
		for _, lost := range []string{"hello", "activation"} {
			t.Run(transport+"/"+lost, func(t *testing.T) {
				f := newConfiguredConnectorFixture(t, transport, "", func(f *connectorFixture, _ *Config) {
					if lost == "hello" {
						f.dropHelloReply[0].Store(true)
					} else {
						f.dropActivationReply[0].Store(true)
					}
				})
				local := f.local(t)
				if _, err := io.WriteString(local, "same initial owner"); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len("same initial owner"))
				if _, err := io.ReadFull(local, got); err != nil || string(got) != "same initial owner" {
					t.Fatal("initial retry changed the application transcript", err)
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				if len(f.peers) != 1 || f.opened.Load() != 1 || f.assignments[0].Load() < 2 || f.assignments[1].Load() != 1 {
					t.Fatal("lost initial reply created another owner, target, or sibling connection")
				}
				operations := f.initialOperations[0]
				if len(operations) == 0 || operations[0] == (tunnelv1.ConnectorHandoffID{}) {
					t.Fatal("initial operation was not retained")
				}
				for _, operation := range operations {
					if operation != operations[0] {
						t.Fatal("uncertain activation changed its stable initial operation")
					}
				}
				if lost == "activation" && (len(operations) != 2 || len(f.helloNonces[0]) != 2 || bytes.Equal(f.helloNonces[0][0], f.helloNonces[0][1])) {
					t.Fatal("initial retry reused its signed hello rather than its operation")
				}
			})
		}
	}
}
