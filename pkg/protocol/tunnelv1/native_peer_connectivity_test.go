package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func connectivityFixture() NativePeerConnectivity {
	return NativePeerConnectivity{ProtocolVersion: Version, Kind: "native_peer_connectivity",
		PairID: "npp_1234567890123456789012", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 1,
		UsernameFragment: "abcd", Password: "abcdefghijklmnopqrstuv", Candidates: []string{"1 1 udp 2130706431 192.0.2.1 4443 typ host"}}
}

func TestNativePeerConnectivityGoldenAndTruncation(t *testing.T) {
	m := connectivityFixture()
	assertGoldenFrame(t, "native-peer-connectivity", m, WriteNativePeerConnectivity, ReadNativePeerConnectivity)
	wire := goldenWire(t, "native-peer-connectivity")
	for length := range len(wire) {
		if _, err := ReadNativePeerConnectivity(bytes.NewReader(wire[:length])); !errors.Is(err, ErrNativePeerConnectivity) {
			t.Fatalf("accepted partial signaling at byte %d: %v", length, err)
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", m, m), m.Password) {
		t.Fatal("formatted connectivity exposed credentials")
	}
}

func TestNativePeerConnectivityRejectsInvalidAndBounds(t *testing.T) {
	for name, change := range map[string]func(*NativePeerConnectivity){
		"version":              func(m *NativePeerConnectivity) { m.ProtocolVersion++ },
		"kind":                 func(m *NativePeerConnectivity) { m.Kind = "other" },
		"pair":                 func(m *NativePeerConnectivity) { m.PairID = "npp_invalid" },
		"delivery":             func(m *NativePeerConnectivity) { m.DeliveryID = strings.Repeat("A", 22) },
		"generation":           func(m *NativePeerConnectivity) { m.DeliveryGeneration = 0 },
		"ufrag-short":          func(m *NativePeerConnectivity) { m.UsernameFragment = "abc" },
		"ufrag-oversize":       func(m *NativePeerConnectivity) { m.UsernameFragment = strings.Repeat("a", 257) },
		"password-short":       func(m *NativePeerConnectivity) { m.Password = "short" },
		"password-oversize":    func(m *NativePeerConnectivity) { m.Password = strings.Repeat("a", 257) },
		"credential-character": func(m *NativePeerConnectivity) { m.Password += "\n" },
		"no-candidates":        func(m *NativePeerConnectivity) { m.Candidates = nil },
		"many-candidates":      func(m *NativePeerConnectivity) { m.Candidates = make([]string, MaxNativePeerCandidates+1) },
		"large-candidate":      func(m *NativePeerConnectivity) { m.Candidates[0] = strings.Repeat("a", 769) },
		"candidate-control":    func(m *NativePeerConnectivity) { m.Candidates[0] += "\n" },
	} {
		t.Run(name, func(t *testing.T) {
			m := connectivityFixture()
			change(&m)
			var output bytes.Buffer
			if err := WriteNativePeerConnectivity(&output, m); !errors.Is(err, ErrNativePeerConnectivity) || output.Len() != 0 {
				t.Fatal("wrote invalid signal", err)
			}
			body, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadNativePeerConnectivity(frame(string(body))); !errors.Is(err, ErrNativePeerConnectivity) {
				t.Fatal("accepted invalid signal", err)
			}
		})
	}
	body, _ := json.Marshal(connectivityFixture())
	for _, invalid := range []string{strings.Replace(string(body), `"pair_id"`, `"unknown"`, 1), strings.TrimSuffix(string(body), "}") + `,"source_ip":"127.0.0.1"}`} {
		if _, err := ReadNativePeerConnectivity(frame(invalid)); !errors.Is(err, ErrNativePeerConnectivity) {
			t.Fatal("accepted unknown or missing field", err)
		}
	}
	for _, size := range []uint32{0, MaxNativePeerConnectivityBytes + 1} {
		if _, err := ReadNativePeerConnectivity(bytes.NewReader(binary.BigEndian.AppendUint32(nil, size))); !errors.Is(err, ErrNativePeerConnectivity) {
			t.Fatal("accepted frame size", size, err)
		}
	}
	m := connectivityFixture()
	m.UsernameFragment, m.Password = strings.Repeat("a", 256), strings.Repeat("b", 256)
	m.Candidates = make([]string, MaxNativePeerCandidates)
	for i := range m.Candidates {
		m.Candidates[i] = strings.Repeat("c", 768)
	}
	var output bytes.Buffer
	if err := WriteNativePeerConnectivity(&output, m); err != nil {
		t.Fatal("rejected maximum bounded fields", err)
	}
	if _, err := ReadNativePeerConnectivity(&output); err != nil {
		t.Fatal(err)
	}
}

func FuzzNativePeerConnectivity(f *testing.F) {
	f.Add(goldenWire(f, "native-peer-connectivity"))
	f.Add([]byte{0, 0, 0, 1, '{'})
	f.Fuzz(func(t *testing.T, data []byte) {
		message, err := ReadNativePeerConnectivity(bytes.NewReader(data))
		if err != nil {
			return
		}
		var output bytes.Buffer
		if err := WriteNativePeerConnectivity(&output, message); err != nil {
			t.Fatal("accepted signal could not be encoded", err)
		}
		if output.Len() > MaxNativePeerConnectivityBytes+4 {
			t.Fatal("unbounded connectivity frame")
		}
	})
}
