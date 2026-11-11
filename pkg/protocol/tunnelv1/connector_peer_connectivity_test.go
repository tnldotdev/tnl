package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
)

func connectorPeerConnectivityFixture() ConnectorPeerConnectivity {
	// credentials are fixed, synthetic fixture values.
	return ConnectorPeerConnectivity{
		ProtocolVersion: Version, Kind: "connector_peer_connectivity",
		PairID: "cpp_1234567890123456789012", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ",
		DeliveryGeneration: 3, Attempt: 7,
		UsernameFragment: "abcdEFGH01234567", Password: "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		Candidates: []string{
			"1 1 udp 2130706431 192.0.2.10 50000 typ host",
			"2 1 udp 1694498815 198.51.100.20 50001 typ srflx raddr 192.0.2.10 rport 50000",
		},
	}
}

var invalidConnectorPeerConnectivityFixtures = []string{
	"invalid-connector-peer-connectivity-unknown-field",
	"invalid-connector-peer-connectivity-null",
	"invalid-connector-peer-connectivity-missing-field",
	"invalid-connector-peer-connectivity-candidate-oversize",
	"invalid-connector-peer-connectivity-candidates-oversize",
	"invalid-connector-peer-connectivity-username-oversize",
	"invalid-connector-peer-connectivity-password-oversize",
	"invalid-connector-peer-connectivity-attempt-zero",
	"invalid-connector-peer-connectivity-attempt-overflow",
	"invalid-connector-peer-connectivity-pair-id",
	"invalid-connector-peer-connectivity-delivery-id",
	"invalid-connector-peer-connectivity-generation-zero",
	"invalid-connector-peer-connectivity-generation-overflow",
}

func assertInvalidConnectorPeerConnectivity(t testing.TB, r io.Reader) {
	t.Helper()
	got, err := ReadConnectorPeerConnectivity(r)
	if !errors.Is(err, ErrConnectorPeerConnectivity) {
		t.Fatal("invalid connectivity did not return its protocol error")
	}
	if !reflect.DeepEqual(got, ConnectorPeerConnectivity{}) {
		t.Fatal("failed connectivity read returned a partial message")
	}
}

func TestConnectorPeerConnectivityInvalidFixtures(t *testing.T) {
	for _, name := range invalidConnectorPeerConnectivityFixtures {
		t.Run(name, func(t *testing.T) {
			assertInvalidConnectorPeerConnectivity(t, frame(string(readFixture(t, name+".json"))))
		})
	}
}

func TestConnectorPeerConnectivityRequiresEveryField(t *testing.T) {
	for _, field := range []string{
		"protocol_version", "kind", "pair_id", "delivery_id", "delivery_generation",
		"attempt", "username_fragment", "password", "candidates",
	} {
		for _, form := range []string{"missing", "null", "wrong type"} {
			t.Run(field+"/"+form, func(t *testing.T) {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(readFixture(t, "connector-peer-connectivity.json"), &fields); err != nil {
					t.Fatal("could not decode connectivity fixture")
				}
				switch form {
				case "missing":
					delete(fields, field)
				case "null":
					fields[field] = json.RawMessage("null")
				case "wrong type":
					fields[field] = json.RawMessage("true")
				}
				payload, err := json.Marshal(fields)
				if err != nil {
					t.Fatal("could not encode invalid connectivity")
				}
				assertInvalidConnectorPeerConnectivity(t, frame(string(payload)))
			})
		}
	}
}

func TestConnectorPeerConnectivityRejectsInvalidValuesBeforeWriting(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*ConnectorPeerConnectivity)
	}{
		{"zero version", func(m *ConnectorPeerConnectivity) { m.ProtocolVersion = 0 }},
		{"future version", func(m *ConnectorPeerConnectivity) { m.ProtocolVersion++ }},
		{"missing kind", func(m *ConnectorPeerConnectivity) { m.Kind = "" }},
		{"foreign kind", func(m *ConnectorPeerConnectivity) { m.Kind = "connector_peer_visitor" }},
		{"missing pair", func(m *ConnectorPeerConnectivity) { m.PairID = "" }},
		{"foreign pair prefix", func(m *ConnectorPeerConnectivity) { m.PairID = "svc_1234567890123456789012" }},
		{"short pair", func(m *ConnectorPeerConnectivity) { m.PairID = "cpp_" + strings.Repeat("A", 21) }},
		{"long pair", func(m *ConnectorPeerConnectivity) { m.PairID += "A" }},
		{"nonalphanumeric pair", func(m *ConnectorPeerConnectivity) { m.PairID = "cpp_" + strings.Repeat("_", 22) }},
		{"missing delivery", func(m *ConnectorPeerConnectivity) { m.DeliveryID = "" }},
		{"zero delivery", func(m *ConnectorPeerConnectivity) { m.DeliveryID = strings.Repeat("A", 22) }},
		{"short delivery", func(m *ConnectorPeerConnectivity) { m.DeliveryID = m.DeliveryID[:21] }},
		{"long delivery", func(m *ConnectorPeerConnectivity) { m.DeliveryID += "A" }},
		{"padded delivery", func(m *ConnectorPeerConnectivity) { m.DeliveryID += "==" }},
		{"noncanonical delivery", func(m *ConnectorPeerConnectivity) { m.DeliveryID = m.DeliveryID[:21] + "R" }},
		{"delivery alphabet", func(m *ConnectorPeerConnectivity) { m.DeliveryID = strings.Repeat("!", 22) }},
		{"zero generation", func(m *ConnectorPeerConnectivity) { m.DeliveryGeneration = 0 }},
		{"negative generation", func(m *ConnectorPeerConnectivity) { m.DeliveryGeneration = -1 }},
		{"zero attempt", func(m *ConnectorPeerConnectivity) { m.Attempt = 0 }},
		{"missing username", func(m *ConnectorPeerConnectivity) { m.UsernameFragment = "" }},
		{"short username", func(m *ConnectorPeerConnectivity) { m.UsernameFragment = "abc" }},
		{"long username", func(m *ConnectorPeerConnectivity) { m.UsernameFragment = strings.Repeat("A", 257) }},
		{"missing password", func(m *ConnectorPeerConnectivity) { m.Password = "" }},
		{"short password", func(m *ConnectorPeerConnectivity) { m.Password = strings.Repeat("A", 21) }},
		{"long password", func(m *ConnectorPeerConnectivity) { m.Password = strings.Repeat("A", 257) }},
		{"nil candidates", func(m *ConnectorPeerConnectivity) { m.Candidates = nil }},
		{"empty candidates", func(m *ConnectorPeerConnectivity) { m.Candidates = []string{} }},
		{"too many candidates", func(m *ConnectorPeerConnectivity) {
			m.Candidates = make([]string, 33)
			for i := range m.Candidates {
				m.Candidates[i] = "x"
			}
		}},
		{"empty candidate", func(m *ConnectorPeerConnectivity) { m.Candidates[0] = "" }},
		{"long candidate", func(m *ConnectorPeerConnectivity) { m.Candidates[0] = strings.Repeat("x", 769) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := connectorPeerConnectivityFixture()
			test.change(&m)
			assertInvalidConnectorPeerConnectivityValue(t, m)
		})
	}
	for _, character := range []byte{0, '\t', '\n', '\r', 31, 127, 128, 255} {
		t.Run(fmt.Sprintf("candidate byte %d", character), func(t *testing.T) {
			m := connectorPeerConnectivityFixture()
			m.Candidates[0] = "candidate" + string([]byte{character})
			assertInvalidConnectorPeerConnectivityValue(t, m)
		})
	}
	for _, field := range []string{"username", "password"} {
		for _, character := range []string{" ", "-", "_", "=", "\x00", "\t", "\n", "\r", "\x7f", "é", "\xff"} {
			t.Run(fmt.Sprintf("%s character %x", field, []byte(character)), func(t *testing.T) {
				m := connectorPeerConnectivityFixture()
				if field == "username" {
					m.UsernameFragment += character
				} else {
					m.Password += character
				}
				assertInvalidConnectorPeerConnectivityValue(t, m)
			})
		}
	}
}

func assertInvalidConnectorPeerConnectivityValue(t testing.TB, m ConnectorPeerConnectivity) {
	t.Helper()
	if !errors.Is(m.Validate(), ErrConnectorPeerConnectivity) {
		t.Fatal("invalid connectivity passed structural validation")
	}
	w := &failingWriter{}
	if err := WriteConnectorPeerConnectivity(w, m); !errors.Is(err, ErrConnectorPeerConnectivity) || w.call != 0 {
		t.Fatal("invalid connectivity reached the frame writer")
	}
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal("could not encode invalid connectivity")
	}
	assertInvalidConnectorPeerConnectivity(t, frame(string(payload)))
}

func assertConnectorPeerConnectivityRoundTrip(t testing.TB, m ConnectorPeerConnectivity) []byte {
	t.Helper()
	if err := m.Validate(); err != nil {
		t.Fatal("valid connectivity failed structural validation")
	}
	var out bytes.Buffer
	if err := WriteConnectorPeerConnectivity(&out, m); err != nil {
		t.Fatal("valid connectivity could not be written")
	}
	if out.Len() < 5 || out.Len() > MaxConnectorPeerConnectivityBytes+4 || int(binary.BigEndian.Uint32(out.Bytes()[:4])) != out.Len()-4 {
		t.Fatal("connectivity writer violated frame bounds")
	}
	wire := bytes.Clone(out.Bytes())
	got, err := ReadConnectorPeerConnectivity(&out)
	if err != nil || !reflect.DeepEqual(got, m) || out.Len() != 0 {
		t.Fatal("connectivity did not round trip as one complete frame")
	}
	return wire
}

func TestConnectorPeerConnectivitySupportedBounds(t *testing.T) {
	if MaxConnectorPeerCandidates != 32 || MaxConnectorPeerConnectivityBytes != 32<<10 {
		t.Fatal("connector peer connectivity wire bounds changed")
	}
	for _, test := range []struct {
		name   string
		change func(*ConnectorPeerConnectivity)
	}{
		{"minimum", func(m *ConnectorPeerConnectivity) {
			m.UsernameFragment, m.Password = "aZ+/", strings.Repeat("a", 22)
			m.DeliveryGeneration, m.Attempt, m.Candidates = 1, 1, []string{" "}
		}},
		{"maximum credentials and counters", func(m *ConnectorPeerConnectivity) {
			m.UsernameFragment, m.Password = strings.Repeat("azAZ09+/", 32), strings.Repeat("Za90/+az", 32)
			m.DeliveryGeneration, m.Attempt = math.MaxInt64, math.MaxUint64
		}},
		{"maximum candidates", func(m *ConnectorPeerConnectivity) {
			m.Candidates = make([]string, 32)
			for i := range m.Candidates {
				m.Candidates[i] = strings.Repeat("x", 768)
			}
		}},
		{"printable candidate alphabet", func(m *ConnectorPeerConnectivity) {
			var candidate strings.Builder
			for character := byte(32); character <= 126; character++ {
				candidate.WriteByte(character)
			}
			m.Candidates = []string{candidate.String()}
		}},
		{"candidate semantics belong to runtime", func(m *ConnectorPeerConnectivity) {
			// protocol validation bounds strings; Pion validates addresses at runtime.
			m.Candidates = []string{"not an ICE candidate", "0.0.0.0", "host.local", "[::ffff:192.0.2.10]"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := connectorPeerConnectivityFixture()
			test.change(&m)
			assertConnectorPeerConnectivityRoundTrip(t, m)
		})
	}
}

func connectorPeerConnectivityAtPayloadSize(t testing.TB, size int) ConnectorPeerConnectivity {
	t.Helper()
	m := connectorPeerConnectivityFixture()
	m.UsernameFragment, m.Password = strings.Repeat("A", 256), strings.Repeat("B", 256)
	m.DeliveryGeneration, m.Attempt = math.MaxInt64, math.MaxUint64
	m.Candidates = make([]string, 32)
	for i := range m.Candidates {
		m.Candidates[i] = strings.Repeat("x", 768)
	}
	payload, err := json.Marshal(m)
	if err != nil {
		t.Fatal("could not encode maximum connectivity")
	}
	// each backslash adds exactly one JSON byte without changing string length.
	growth := size - len(payload)
	if growth < 0 || growth > 32*768 {
		t.Fatal("requested fixture size cannot be built within structural bounds")
	}
	for i := range m.Candidates {
		escapes := min(growth, 768)
		m.Candidates[i] = strings.Repeat("\\", escapes) + strings.Repeat("x", 768-escapes)
		growth -= escapes
	}
	payload, err = json.Marshal(m)
	if err != nil || len(payload) != size || m.Validate() != nil {
		t.Fatal("could not build structurally valid connectivity at the requested wire size")
	}
	return m
}

func TestConnectorPeerConnectivityAggregateWireBounds(t *testing.T) {
	atLimit := connectorPeerConnectivityAtPayloadSize(t, 32<<10)
	wire := assertConnectorPeerConnectivityRoundTrip(t, atLimit)
	if len(wire) != (32<<10)+4 {
		t.Fatal("maximum connectivity payload did not reach its exact wire limit")
	}
	overLimit := connectorPeerConnectivityAtPayloadSize(t, (32<<10)+1)
	w := &failingWriter{}
	if err := WriteConnectorPeerConnectivity(w, overLimit); err == nil || w.call != 0 {
		t.Fatal("over-limit connectivity wrote frame bytes")
	}
	// HTML escaping turns one printable character into six JSON bytes.
	for i := range overLimit.Candidates {
		overLimit.Candidates[i] = strings.Repeat("<", 768)
	}
	if overLimit.Validate() != nil {
		t.Fatal("JSON expansion changed structural candidate validation")
	}
	if err := WriteConnectorPeerConnectivity(w, overLimit); err == nil || w.call != 0 {
		t.Fatal("escaped over-limit connectivity wrote frame bytes")
	}
	// a peer can send literal printable characters without JSON's HTML escaping.
	payload, err := json.Marshal(overLimit)
	if err != nil {
		t.Fatal("could not encode expanded connectivity")
	}
	payload = bytes.ReplaceAll(payload, []byte(`\u003c`), []byte("<"))
	if len(payload) > MaxConnectorPeerConnectivityBytes {
		t.Fatal("literal candidate payload did not fit the input frame bound")
	}
	got, err := ReadConnectorPeerConnectivity(frame(string(payload)))
	if err != nil || !reflect.DeepEqual(got, overLimit) {
		t.Fatal("reader applied JSON expansion instead of its input frame bound")
	}
}

func TestConnectorPeerConnectivityMalformedWireReturnsNoPartialMessage(t *testing.T) {
	for _, payload := range []string{
		"", "{}", "[]", "true", `"connectivity"`,
		`{"protocol_version":1,`,
	} {
		assertInvalidConnectorPeerConnectivity(t, frame(payload))
	}
	for _, field := range []struct{ name, value string }{
		{"attempt", "-1"}, {"attempt", "1.5"}, {"attempt", "18446744073709551616"},
		{"delivery_generation", "-1"}, {"delivery_generation", "1.5"}, {"delivery_generation", "9223372036854775808"},
		{"protocol_version", "4294967296"}, {"candidates", "[null]"}, {"candidates", "[42]"},
	} {
		t.Run(field.name+"/"+field.value, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(readFixture(t, "connector-peer-connectivity.json"), &fields); err != nil {
				t.Fatal("could not decode connectivity fixture")
			}
			fields[field.name] = json.RawMessage(field.value)
			payload, err := json.Marshal(fields)
			if err != nil {
				t.Fatal("could not encode malformed connectivity")
			}
			assertInvalidConnectorPeerConnectivity(t, frame(string(payload)))
		})
	}
	wire := goldenWire(t, "connector-peer-connectivity")
	for _, length := range []int{0, 1, 3, 4, len(wire) - 1} {
		_, err := ReadConnectorPeerConnectivity(bytes.NewReader(wire[:length]))
		want := io.ErrUnexpectedEOF
		if length == 0 || length == 4 {
			want = io.EOF
		}
		if !errors.Is(err, ErrConnectorPeerConnectivity) || !errors.Is(err, want) {
			t.Fatal("truncated connectivity lost its protocol or underlying read error")
		}
		assertInvalidConnectorPeerConnectivity(t, bytes.NewReader(wire[:length]))
	}
}

func TestConnectorPeerConnectivityFormattingDoesNotExposeCredentials(t *testing.T) {
	m := connectorPeerConnectivityFixture()
	m.UsernameFragment, m.Password = "ConnectivityUserSecret1234", "ConnectivityPasswordSecret0123456789"
	const label = "connector peer connectivity"
	if m.String() != label || m.GoString() != label || (&m).String() != label || (&m).GoString() != label {
		t.Fatal("connectivity String or GoString did not return its secret-free label")
	}
	for _, value := range []any{m, &m} {
		for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
			formatted := fmt.Sprintf(verb, value)
			want := label
			if verb == "%q" {
				want = `"` + label + `"`
			}
			if formatted != want || strings.Contains(formatted, m.UsernameFragment) || strings.Contains(formatted, m.Password) {
				t.Fatal("connectivity formatting exposed fields instead of its secret-free label")
			}
		}
	}
	for _, value := range []any{[]ConnectorPeerConnectivity{m}, struct{ Message ConnectorPeerConnectivity }{m}} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			formatted := fmt.Sprintf(verb, value)
			if strings.Contains(formatted, m.UsernameFragment) || strings.Contains(formatted, m.Password) {
				t.Fatal("nested connectivity formatting exposed credentials")
			}
		}
	}
}

func FuzzConnectorPeerConnectivity(f *testing.F) {
	golden := goldenWire(f, "connector-peer-connectivity")
	f.Add(golden, uint8(1))
	f.Add(append(bytes.Clone(golden), []byte("next frame or visitor bytes")...), uint8(13))
	atLimit := assertConnectorPeerConnectivityRoundTrip(f, connectorPeerConnectivityAtPayloadSize(f, 32<<10))
	f.Add(atLimit, uint8(31))
	// literal candidates fit on input but expand beyond the output cap.
	literal := bytes.ReplaceAll(atLimit[4:], []byte(`\\`), []byte("<"))
	f.Add(append(binary.BigEndian.AppendUint32(nil, uint32(len(literal))), literal...), uint8(15))
	for _, name := range invalidConnectorPeerConnectivityFixtures {
		payload := readFixture(f, name+".json")
		wire := append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...)
		f.Add(wire, uint8(7))
	}
	f.Add([]byte{}, uint8(0))
	f.Add(binary.BigEndian.AppendUint32(nil, ^uint32(0)), uint8(3))
	f.Fuzz(func(t *testing.T, input []byte, readSize uint8) {
		source := bytes.NewReader(input)
		r := &limitedReader{Reader: source, Size: int(readSize%32) + 1}
		m, err := ReadConnectorPeerConnectivity(r)
		if err != nil {
			if !errors.Is(err, ErrConnectorPeerConnectivity) || !reflect.DeepEqual(m, ConnectorPeerConnectivity{}) {
				t.Fatal("failed connectivity read lost its protocol error or returned a partial message")
			}
			return
		}
		if len(input) < 4 || source.Len() != len(input)-4-int(binary.BigEndian.Uint32(input[:4])) {
			t.Fatal("connectivity reader consumed beyond its frame")
		}
		payload, err := json.Marshal(m)
		if err != nil || m.Validate() != nil {
			t.Fatal("accepted connectivity failed structural validation or JSON encoding")
		}
		if len(payload) > MaxConnectorPeerConnectivityBytes {
			// input can fit the cap while canonical JSON escaping exceeds it.
			w := &failingWriter{}
			if err := WriteConnectorPeerConnectivity(w, m); err == nil || w.call != 0 {
				t.Fatal("expanded accepted connectivity wrote an over-limit frame")
			}
			return
		}
		assertConnectorPeerConnectivityRoundTrip(t, m)
	})
}
