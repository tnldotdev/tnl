package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func peerOpeningFixture() NativePeerVisitorEntry {
	return NativePeerVisitorEntry{ProtocolVersion: Version, Kind: NativePeerVisitorStream,
		PairID: "npp_1234567890123456789012", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 3,
		ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 4,
		Subject:  VisitorSubject{Kind: VisitorHumanDevice, IdentityID: "ident_1234567890123456789012", DeviceID: "vdev_1234567890123456789012"},
		SourceIP: "192.0.2.10", VisitorConnectionID: "vc_1234567890123456789012", MetadataRevision: 5,
		Permission: NativeVisitorPermission{Token: "token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}}
}

func TestPeerNativeVisitorOpeningGolden(t *testing.T) {
	e := peerOpeningFixture()
	assertGoldenFrame(t, "native-peer-visitor-entry", e, WriteNativePeerVisitorEntry, ReadNativePeerVisitorEntry)
	var wire bytes.Buffer
	initial := []byte("hello")
	if sent, err := WriteNativePeerVisitorOpening(&wire, e, initial); err != nil || !sent {
		t.Fatal("writing opening", err)
	}
	want := append(goldenWire(t, "native-peer-visitor-entry"), binary.BigEndian.AppendUint32(nil, uint32(len(initial)))...)
	want = append(want, initial...)
	if !bytes.Equal(wire.Bytes(), want) {
		t.Fatalf("opening = %x; want %x", wire.Bytes(), want)
	}
	got, data, err := ReadNativePeerVisitorOpening(bytes.NewReader(want))
	if err != nil || !reflect.DeepEqual(got, e) || !bytes.Equal(data, initial) {
		t.Fatal("opening did not round trip", err)
	}
	for length := range want {
		if _, _, err := ReadNativePeerVisitorOpening(bytes.NewReader(want[:length])); err == nil {
			t.Fatalf("accepted truncated opening at %d", length)
		}
	}
	if _, _, err := ReadNativePeerVisitorOpening(bytes.NewReader(append(bytes.Clone(want), 0))); err != nil {
		t.Fatal("opening consumed subsequent request data", err)
	}
}

func TestPeerNativeVisitorOpeningRejectsInvalidAndOversize(t *testing.T) {
	for name, change := range map[string]func(*NativePeerVisitorEntry){
		"version":    func(e *NativePeerVisitorEntry) { e.ProtocolVersion++ },
		"kind":       func(e *NativePeerVisitorEntry) { e.Kind = ConnectorVisitorStream },
		"pair":       func(e *NativePeerVisitorEntry) { e.PairID = "npp_wrong" },
		"delivery":   func(e *NativePeerVisitorEntry) { e.DeliveryID = strings.Repeat("A", 22) },
		"generation": func(e *NativePeerVisitorEntry) { e.DeliveryGeneration = 0 },
		"service":    func(e *NativePeerVisitorEntry) { e.ServiceID = testOpaqueID(opaqueid.PublicURLPrefix) },
		"run":        func(e *NativePeerVisitorEntry) { e.ServiceRunID = "invalid" },
		"run number": func(e *NativePeerVisitorEntry) { e.RunNumber = 0 },
		"subject":    func(e *NativePeerVisitorEntry) { e.Subject.Kind = "browser" },
		"source":     func(e *NativePeerVisitorEntry) { e.SourceIP = "::ffff:192.0.2.10" },
		"visitor":    func(e *NativePeerVisitorEntry) { e.VisitorConnectionID = "invalid" },
		"metadata":   func(e *NativePeerVisitorEntry) { e.MetadataRevision = 0 },
		"token":      func(e *NativePeerVisitorEntry) { e.Permission.Token = "" },
		"key":        func(e *NativePeerVisitorEntry) { e.Permission.PublicKey = "invalid" },
		"signature":  func(e *NativePeerVisitorEntry) { e.Permission.Signature = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			e := peerOpeningFixture()
			change(&e)
			var wire bytes.Buffer
			if _, err := WriteNativePeerVisitorOpening(&wire, e, nil); !errors.Is(err, ErrNativePeerVisitorOpening) || wire.Len() != 0 {
				t.Fatal("invalid entry wrote opening", err)
			}
			payload, _ := json.Marshal(e)
			if _, _, err := ReadNativePeerVisitorOpening(frame(string(payload))); err == nil {
				t.Fatal("accepted invalid entry")
			}
		})
	}
	for _, name := range []string{"invalid-native-peer-unknown-field", "invalid-native-peer-missing-field", "invalid-native-peer-wrong-subject"} {
		if _, err := ReadNativePeerVisitorEntry(frame(string(readFixture(t, name+".json")))); err == nil {
			t.Fatal("accepted invalid fixture", name)
		}
	}
	valid := goldenWire(t, "native-peer-visitor-entry")
	for _, size := range []uint32{0, MaxHeaderBytes + 1} {
		if _, err := ReadNativePeerVisitorEntry(bytes.NewReader(binary.BigEndian.AppendUint32(nil, size))); err == nil {
			t.Fatal("accepted invalid header length", size)
		}
	}
	tooLarge := append(bytes.Clone(valid), binary.BigEndian.AppendUint32(nil, MaxInitialBytes+1)...)
	if _, _, err := ReadNativePeerVisitorOpening(bytes.NewReader(tooLarge)); err == nil {
		t.Fatal("accepted oversized initial block")
	}
	var wire bytes.Buffer
	if _, err := WriteNativePeerVisitorOpening(&wire, peerOpeningFixture(), make([]byte, MaxInitialBytes+1)); err == nil || wire.Len() != 0 {
		t.Fatal("oversized opening wrote bytes")
	}
	if _, err := NativePeerProofMessage(peerOpeningFixture(), make([]byte, MaxInitialBytes+1)); err == nil {
		t.Fatal("oversized proof was signed")
	}
	if _, err := NativePeerProofMessage(peerOpeningFixture(), make([]byte, MaxInitialBytes)); err != nil {
		t.Fatal("rejected maximum initial block", err)
	}
	if _, err := WriteNativePeerVisitorOpening(&wire, peerOpeningFixture(), make([]byte, MaxInitialBytes)); err != nil {
		t.Fatal("rejected maximum opening", err)
	}
	if _, initial, err := ReadNativePeerVisitorOpening(&wire); err != nil || len(initial) != MaxInitialBytes {
		t.Fatal("maximum opening did not round trip", err)
	}
}

func TestPeerNativeProofMessageBindsEveryField(t *testing.T) {
	e := peerOpeningFixture()
	initial := []byte("hello")
	want, err := NativePeerProofMessage(e, initial)
	if err != nil || !bytes.HasPrefix(want, []byte("tnl native peer visitor opening v1\x00")) {
		t.Fatal("proof domain missing", err)
	}
	for name, change := range map[string]func(*NativePeerVisitorEntry){
		"pair":       func(e *NativePeerVisitorEntry) { e.PairID = "npp_" + strings.Repeat("Z", 22) },
		"delivery":   func(e *NativePeerVisitorEntry) { e.DeliveryID = "AgICAgICAgICAgICAgICAg" },
		"generation": func(e *NativePeerVisitorEntry) { e.DeliveryGeneration++ },
		"service":    func(e *NativePeerVisitorEntry) { e.ServiceID = "svc_" + strings.Repeat("Z", 22) },
		"run":        func(e *NativePeerVisitorEntry) { e.ServiceRunID = "srun_" + strings.Repeat("Z", 22) },
		"run number": func(e *NativePeerVisitorEntry) { e.RunNumber++ },
		"subject":    func(e *NativePeerVisitorEntry) { e.Subject.DeviceID = "vdev_" + strings.Repeat("Z", 22) },
		"visitor":    func(e *NativePeerVisitorEntry) { e.VisitorConnectionID = "vc_" + strings.Repeat("Z", 22) },
		"metadata":   func(e *NativePeerVisitorEntry) { e.MetadataRevision++ },
		"token":      func(e *NativePeerVisitorEntry) { e.Permission.Token = "new-token" },
		"source":     func(e *NativePeerVisitorEntry) { e.SourceIP = "192.0.2.11" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := e
			change(&changed)
			got, err := NativePeerProofMessage(changed, initial)
			if err != nil || bytes.Equal(got, want) {
				t.Fatal("field not bound to proof", err)
			}
		})
	}
	if changed, err := NativePeerProofMessage(e, []byte("other bytes")); err != nil || bytes.Equal(changed, want) {
		t.Fatal("initial bytes not bound to proof", err)
	}
}

func FuzzPeerNativeVisitorOpening(f *testing.F) {
	valid := goldenWire(f, "native-peer-visitor-entry")
	f.Add(append(append(bytes.Clone(valid), binary.BigEndian.AppendUint32(nil, 5)...), "hello"...))
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		r := &limitedReader{Reader: bytes.NewReader(input), Size: 7}
		e, initial, err := ReadNativePeerVisitorOpening(r)
		if err != nil {
			return
		}
		var out bytes.Buffer
		if _, err := WriteNativePeerVisitorOpening(&out, e, initial); err != nil || out.Len() > MaxHeaderBytes+MaxInitialBytes+8 {
			t.Fatal("accepted opening could not be written within bounds", err)
		}
	})
}
