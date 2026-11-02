package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type openingWriter struct {
	bytes.Buffer
	calls int
	limit int
}

func (w *openingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.limit >= 0 && len(p) > w.limit {
		return w.Buffer.Write(p[:w.limit])
	}
	return w.Buffer.Write(p)
}

func peerOpeningFixture() ConnectorPeerVisitorEntry {
	return ConnectorPeerVisitorEntry{ProtocolVersion: Version, Kind: ConnectorPeerVisitorStream,
		PairID: "cpp_1234567890123456789012", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 3,
		ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 4,
		Subject:  VisitorSubject{Kind: VisitorHumanDevice, IdentityID: "ident_1234567890123456789012", DeviceID: "vdev_1234567890123456789012"},
		SourceIP: "192.0.2.10", VisitorConnectionID: "vc_1234567890123456789012", MetadataRevision: 5,
		Permission: ConnectorVisitorPermission{Token: "token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}}
}

func TestOpeningConnectorPermissionAndInitialBytesStayBoundedAndSeparate(t *testing.T) {
	entry := peerOpeningFixture()
	initial := []byte{0x16, 3, 1, 0, 2, 1, 0}
	writer := &openingWriter{limit: -1}
	if committed, err := WriteConnectorPeerVisitorOpening(writer, entry, initial); err != nil || !committed || writer.calls != 1 {
		t.Fatal("connector opening did not combine permission and initial bytes", err)
	}
	wire := bytes.Clone(writer.Bytes())
	reader := bytes.NewReader(append(wire, []byte("subsequent native bytes")...))
	got, payload, err := ReadConnectorPeerVisitorOpening(reader)
	if err != nil || got != entry || !bytes.Equal(payload, initial) {
		t.Fatal("connector opening changed signed proof or initial bytes", err)
	}
	rest, _ := io.ReadAll(reader)
	if string(rest) != "subsequent native bytes" {
		t.Fatal("connector opening consumed following protocol bytes")
	}
	for length := range len(wire) {
		if _, _, err := ReadConnectorPeerVisitorOpening(bytes.NewReader(wire[:length])); err == nil {
			t.Fatalf("connector opening accepted truncation at %d", length)
		}
	}
	writer.Reset()
	writer.calls = 0
	if _, err := WriteConnectorPeerVisitorOpening(writer, entry, make([]byte, MaxInitialBytes+1)); err == nil || writer.calls != 0 {
		t.Fatal("oversized native initial bytes reached the stream")
	}
	for _, change := range []func(*ConnectorPeerVisitorEntry){
		func(e *ConnectorPeerVisitorEntry) { e.MetadataRevision = 0 },
		func(e *ConnectorPeerVisitorEntry) { e.VisitorConnectionID = "" },
		func(e *ConnectorPeerVisitorEntry) { e.Permission.Token = strings.Repeat("a", 2049) },
		func(e *ConnectorPeerVisitorEntry) { e.Permission.PublicKey = "invalid" },
		func(e *ConnectorPeerVisitorEntry) { e.Permission.Signature = "invalid" },
	} {
		bad := entry
		change(&bad)
		writer.Reset()
		writer.calls = 0
		if _, err := WriteConnectorPeerVisitorOpening(writer, bad, nil); err == nil || writer.calls != 0 {
			t.Fatal("incomplete connector proof reached the stream")
		}
	}
}

func TestPeerConnectorVisitorOpeningGolden(t *testing.T) {
	e := peerOpeningFixture()
	assertGoldenFrame(t, "connector-peer-visitor-entry", e, WriteConnectorPeerVisitorEntry, ReadConnectorPeerVisitorEntry)
	var wire bytes.Buffer
	initial := []byte("hello")
	if sent, err := WriteConnectorPeerVisitorOpening(&wire, e, initial); err != nil || !sent {
		t.Fatal("writing opening", err)
	}
	want := append(goldenWire(t, "connector-peer-visitor-entry"), binary.BigEndian.AppendUint32(nil, uint32(len(initial)))...)
	want = append(want, initial...)
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("opening = %x; want %x", wire.Bytes(), want)
	}
	got, data, err := ReadConnectorPeerVisitorOpening(bytes.NewReader(want))
	if err != nil || !reflect.DeepEqual(got, e) || !bytes.Equal(data, initial) {
		t.Fatal("opening did not round trip", err)
	}
	for length := range want {
		if _, _, err := ReadConnectorPeerVisitorOpening(bytes.NewReader(want[:length])); err == nil {
			t.Fatalf("accepted truncated opening at %d", length)
		}
	}
	if _, _, err := ReadConnectorPeerVisitorOpening(bytes.NewReader(append(bytes.Clone(want), 0))); err != nil {
		t.Fatal("opening consumed subsequent request data", err)
	}
}

func TestPeerConnectorVisitorOpeningRejectsInvalidAndOversize(t *testing.T) {
	for name, change := range map[string]func(*ConnectorPeerVisitorEntry){
		"version":    func(e *ConnectorPeerVisitorEntry) { e.ProtocolVersion++ },
		"kind":       func(e *ConnectorPeerVisitorEntry) { e.Kind = "connector_visitor" },
		"pair":       func(e *ConnectorPeerVisitorEntry) { e.PairID = "cpp_wrong" },
		"delivery":   func(e *ConnectorPeerVisitorEntry) { e.DeliveryID = strings.Repeat("A", 22) },
		"generation": func(e *ConnectorPeerVisitorEntry) { e.DeliveryGeneration = 0 },
		"service":    func(e *ConnectorPeerVisitorEntry) { e.ServiceID = testOpaqueID(opaqueid.PublicURLPrefix) },
		"run":        func(e *ConnectorPeerVisitorEntry) { e.ServiceRunID = "invalid" },
		"run number": func(e *ConnectorPeerVisitorEntry) { e.RunNumber = 0 },
		"subject":    func(e *ConnectorPeerVisitorEntry) { e.Subject.Kind = "browser" },
		"source":     func(e *ConnectorPeerVisitorEntry) { e.SourceIP = "::ffff:192.0.2.10" },
		"visitor":    func(e *ConnectorPeerVisitorEntry) { e.VisitorConnectionID = "invalid" },
		"metadata":   func(e *ConnectorPeerVisitorEntry) { e.MetadataRevision = 0 },
		"token":      func(e *ConnectorPeerVisitorEntry) { e.Permission.Token = "" },
		"key":        func(e *ConnectorPeerVisitorEntry) { e.Permission.PublicKey = "invalid" },
		"signature":  func(e *ConnectorPeerVisitorEntry) { e.Permission.Signature = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			e := peerOpeningFixture()
			change(&e)
			var wire bytes.Buffer
			if _, err := WriteConnectorPeerVisitorOpening(&wire, e, nil); !errors.Is(err, ErrConnectorPeerVisitorOpening) || wire.Len() != 0 {
				t.Fatal("invalid entry wrote opening", err)
			}
			payload, _ := json.Marshal(e)
			if _, _, err := ReadConnectorPeerVisitorOpening(frame(string(payload))); err == nil {
				t.Fatal("accepted invalid entry")
			}
		})
	}
	for _, name := range []string{"invalid-connector-peer-unknown-field", "invalid-connector-peer-missing-field", "invalid-connector-peer-wrong-subject"} {
		if _, err := ReadConnectorPeerVisitorEntry(frame(string(readFixture(t, name+".json")))); err == nil {
			t.Fatal("accepted invalid fixture", name)
		}
	}
	valid := goldenWire(t, "connector-peer-visitor-entry")
	for _, size := range []uint32{0, MaxHeaderBytes + 1} {
		if _, err := ReadConnectorPeerVisitorEntry(bytes.NewReader(binary.BigEndian.AppendUint32(nil, size))); err == nil {
			t.Fatal("accepted invalid header length", size)
		}
	}
	tooLarge := append(bytes.Clone(valid), binary.BigEndian.AppendUint32(nil, MaxInitialBytes+1)...)
	if _, _, err := ReadConnectorPeerVisitorOpening(bytes.NewReader(tooLarge)); err == nil {
		t.Fatal("accepted oversized initial block")
	}
	var wire bytes.Buffer
	if _, err := WriteConnectorPeerVisitorOpening(&wire, peerOpeningFixture(), make([]byte, MaxInitialBytes+1)); err == nil || wire.Len() != 0 {
		t.Fatal("oversized opening wrote bytes")
	}
	if _, err := ConnectorPeerProofMessage(peerOpeningFixture(), make([]byte, MaxInitialBytes+1)); err == nil {
		t.Fatal("oversized proof was signed")
	}
	if _, err := ConnectorPeerProofMessage(peerOpeningFixture(), make([]byte, MaxInitialBytes)); err != nil {
		t.Fatal("rejected maximum initial block", err)
	}
	if _, err := WriteConnectorPeerVisitorOpening(&wire, peerOpeningFixture(), make([]byte, MaxInitialBytes)); err != nil {
		t.Fatal("rejected maximum opening", err)
	}
	if _, initial, err := ReadConnectorPeerVisitorOpening(&wire); err != nil || len(initial) != MaxInitialBytes {
		t.Fatal("maximum opening did not round trip", err)
	}
}

func TestPeerConnectorProofMessageBindsEveryField(t *testing.T) {
	e := peerOpeningFixture()
	initial := []byte("hello")
	want, err := ConnectorPeerProofMessage(e, initial)
	if err != nil || !bytes.HasPrefix(want, []byte("tnl connector peer visitor opening v1\x00")) {
		t.Fatal("proof domain missing", err)
	}
	for name, change := range map[string]func(*ConnectorPeerVisitorEntry){
		"pair":       func(e *ConnectorPeerVisitorEntry) { e.PairID = "cpp_" + strings.Repeat("Z", 22) },
		"delivery":   func(e *ConnectorPeerVisitorEntry) { e.DeliveryID = "AgICAgICAgICAgICAgICAg" },
		"generation": func(e *ConnectorPeerVisitorEntry) { e.DeliveryGeneration++ },
		"service":    func(e *ConnectorPeerVisitorEntry) { e.ServiceID = "svc_" + strings.Repeat("Z", 22) },
		"run":        func(e *ConnectorPeerVisitorEntry) { e.ServiceRunID = "srun_" + strings.Repeat("Z", 22) },
		"run number": func(e *ConnectorPeerVisitorEntry) { e.RunNumber++ },
		"subject":    func(e *ConnectorPeerVisitorEntry) { e.Subject.DeviceID = "vdev_" + strings.Repeat("Z", 22) },
		"visitor":    func(e *ConnectorPeerVisitorEntry) { e.VisitorConnectionID = "vc_" + strings.Repeat("Z", 22) },
		"metadata":   func(e *ConnectorPeerVisitorEntry) { e.MetadataRevision++ },
		"token":      func(e *ConnectorPeerVisitorEntry) { e.Permission.Token = "new-token" },
		"source":     func(e *ConnectorPeerVisitorEntry) { e.SourceIP = "192.0.2.11" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := e
			change(&changed)
			got, err := ConnectorPeerProofMessage(changed, initial)
			if err != nil || bytes.Equal(got, want) {
				t.Fatal("field not bound to proof", err)
			}
		})
	}
	if changed, err := ConnectorPeerProofMessage(e, []byte("other bytes")); err != nil || bytes.Equal(changed, want) {
		t.Fatal("initial bytes not bound to proof", err)
	}
}

func FuzzPeerConnectorVisitorOpening(f *testing.F) {
	valid := goldenWire(f, "connector-peer-visitor-entry")
	f.Add(append(append(bytes.Clone(valid), binary.BigEndian.AppendUint32(nil, 5)...), "hello"...))
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		r := &limitedReader{Reader: bytes.NewReader(input), Size: 7}
		e, initial, err := ReadConnectorPeerVisitorOpening(r)
		if err != nil {
			return
		}
		var out bytes.Buffer
		if _, err := WriteConnectorPeerVisitorOpening(&out, e, initial); err != nil || out.Len() > MaxHeaderBytes+MaxInitialBytes+8 {
			t.Fatal("accepted opening could not be written within bounds", err)
		}
	})
}
