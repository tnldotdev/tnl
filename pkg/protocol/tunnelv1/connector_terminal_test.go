package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"slices"
	"strings"
	"testing"
)

type connectorTerminalWireFixture struct {
	name    string
	payload string
	message any
}

func connectorTerminalResultFixture(purpose ConnectorTerminalPurpose, outcome ConnectorTerminalOutcome) ConnectorVisitorTerminalResult {
	return ConnectorVisitorTerminalResult{
		Kind: ConnectorVisitorTerminalResultKind, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa",
		DeliveryGeneration: 7, TerminalNumber: 1, Purpose: purpose, Outcome: outcome,
	}
}

func connectorTerminalObservedFixture(purpose ConnectorTerminalPurpose, outcome ConnectorTerminalOutcome) ConnectorVisitorTerminalObserved {
	return ConnectorVisitorTerminalObserved{
		Kind: ConnectorVisitorTerminalObservedKind, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa",
		DeliveryGeneration: 7, TerminalNumber: 1, Purpose: purpose, Outcome: outcome,
	}
}

func connectorTerminalWireFixtures() []connectorTerminalWireFixture {
	return []connectorTerminalWireFixture{
		{"completion", `{"kind":"connector_visitor_completed","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1}`,
			ConnectorVisitorCompletion{Kind: ConnectorVisitorCompleted, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7, TerminalNumber: 1}},
		{"abort", `{"kind":"connector_visitor_aborted","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1}`,
			ConnectorVisitorAbort{Kind: ConnectorVisitorAborted, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7, TerminalNumber: 1}},
		{"completion-accepted", `{"kind":"connector_visitor_terminal_result","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"completion","outcome":"accepted"}`,
			connectorTerminalResultFixture(ConnectorTerminalCompletion, ConnectorTerminalAccepted)},
		{"completion-rejected", `{"kind":"connector_visitor_terminal_result","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"completion","outcome":"rejected"}`,
			connectorTerminalResultFixture(ConnectorTerminalCompletion, ConnectorTerminalRejected)},
		{"completion-failed", `{"kind":"connector_visitor_terminal_result","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"completion","outcome":"failed"}`,
			connectorTerminalResultFixture(ConnectorTerminalCompletion, ConnectorTerminalFailed)},
		{"abort-accepted", `{"kind":"connector_visitor_terminal_result","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"abort","outcome":"accepted"}`,
			connectorTerminalResultFixture(ConnectorTerminalAbort, ConnectorTerminalAccepted)},
		{"abort-rejected", `{"kind":"connector_visitor_terminal_result","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"abort","outcome":"rejected"}`,
			connectorTerminalResultFixture(ConnectorTerminalAbort, ConnectorTerminalRejected)},
		{"abort-failed", `{"kind":"connector_visitor_terminal_result","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"abort","outcome":"failed"}`,
			connectorTerminalResultFixture(ConnectorTerminalAbort, ConnectorTerminalFailed)},
		{"completion-accepted-observed", `{"kind":"connector_visitor_terminal_observed","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"completion","outcome":"accepted"}`,
			connectorTerminalObservedFixture(ConnectorTerminalCompletion, ConnectorTerminalAccepted)},
		{"completion-failed-observed", `{"kind":"connector_visitor_terminal_observed","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"completion","outcome":"failed"}`,
			connectorTerminalObservedFixture(ConnectorTerminalCompletion, ConnectorTerminalFailed)},
		{"abort-accepted-observed", `{"kind":"connector_visitor_terminal_observed","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"abort","outcome":"accepted"}`,
			connectorTerminalObservedFixture(ConnectorTerminalAbort, ConnectorTerminalAccepted)},
		{"abort-failed-observed", `{"kind":"connector_visitor_terminal_observed","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":7,"terminal_number":1,"purpose":"abort","outcome":"failed"}`,
			connectorTerminalObservedFixture(ConnectorTerminalAbort, ConnectorTerminalFailed)},
	}
}

func connectorTerminalMaximumWireFixtures() []connectorTerminalWireFixture {
	result := connectorTerminalResultFixture(ConnectorTerminalCompletion, ConnectorTerminalAccepted)
	result.DeliveryGeneration, result.TerminalNumber = math.MaxInt64, math.MaxUint64
	observed := connectorTerminalObservedFixture(ConnectorTerminalCompletion, ConnectorTerminalAccepted)
	observed.DeliveryGeneration, observed.TerminalNumber = math.MaxInt64, math.MaxUint64
	return []connectorTerminalWireFixture{
		{"completion-maximum", `{"kind":"connector_visitor_completed","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":9223372036854775807,"terminal_number":18446744073709551615}`,
			ConnectorVisitorCompletion{Kind: ConnectorVisitorCompleted, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: math.MaxInt64, TerminalNumber: math.MaxUint64}},
		{"abort-maximum", `{"kind":"connector_visitor_aborted","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":9223372036854775807,"terminal_number":18446744073709551615}`,
			ConnectorVisitorAbort{Kind: ConnectorVisitorAborted, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: math.MaxInt64, TerminalNumber: math.MaxUint64}},
		{"result-maximum", `{"kind":"connector_visitor_terminal_result","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":9223372036854775807,"terminal_number":18446744073709551615,"purpose":"completion","outcome":"accepted"}`,
			result},
		{"observed-maximum", `{"kind":"connector_visitor_terminal_observed","visitor_connection_id":"vc_aaaaaaaaaaaaaaaaaaaaaa","delivery_generation":9223372036854775807,"terminal_number":18446744073709551615,"purpose":"completion","outcome":"accepted"}`,
			observed},
	}
}

func connectorTerminalFrame(payload string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...)
}

func writeConnectorTerminalFixture(w io.Writer, message any) error {
	switch message := message.(type) {
	case ConnectorVisitorCompletion:
		return WriteConnectorVisitorCompletion(w, message)
	case ConnectorVisitorAbort:
		return WriteConnectorVisitorAbort(w, message)
	case ConnectorVisitorTerminalResult:
		return WriteConnectorVisitorTerminalResult(w, message)
	case ConnectorVisitorTerminalObserved:
		return WriteConnectorVisitorTerminalObserved(w, message)
	default:
		return ErrConnectorPermissionUpdate
	}
}

func readConnectorTerminalFixture(r io.Reader, message any) (any, error) {
	if _, reply := message.(ConnectorControlReply); reply {
		return ReadConnectorControlReply(r)
	}
	return ReadConnectorControlMessage(r)
}

func TestConnectorTerminalWireGoldenAndTruncation(t *testing.T) {
	for _, fixture := range append(connectorTerminalWireFixtures(), connectorTerminalMaximumWireFixtures()...) {
		t.Run(fixture.name, func(t *testing.T) {
			if len(fixture.payload) > MaxConnectorTerminalBytes {
				t.Fatal("supported terminal number exceeded the existing frame cap")
			}
			wire := connectorTerminalFrame(fixture.payload)
			var encoded bytes.Buffer
			if err := writeConnectorTerminalFixture(&encoded, fixture.message); err != nil || !bytes.Equal(encoded.Bytes(), wire) {
				t.Fatal("terminal frame differs from its literal golden", err)
			}
			got, err := readConnectorTerminalFixture(bytes.NewReader(wire), fixture.message)
			if err != nil || got != fixture.message {
				t.Fatal("terminal frame lost its exact decision", got, err)
			}
			for n := range len(wire) {
				want := io.ErrUnexpectedEOF
				if n == 0 {
					want = io.EOF
				}
				if _, err := readConnectorTerminalFixture(bytes.NewReader(wire[:n]), fixture.message); !errors.Is(err, want) {
					t.Fatal("terminal truncation lost its framing provenance", n, err, want)
				}
			}
			if _, reply := fixture.message.(ConnectorControlReply); reply {
				if got, err := ReadConnectorControlMessage(bytes.NewReader(wire)); err != ErrConnectorPermissionUpdate || got != nil {
					t.Fatal("a reply became a connector request", got, err)
				}
			} else if got, err := ReadConnectorControlReply(bytes.NewReader(wire)); err != ErrConnectorPermissionUpdate || got != nil {
				t.Fatal("a request became a publisher reply", got, err)
			}
			if _, err := ReadConnectorPermissionUpdate(bytes.NewReader(wire)); err != ErrConnectorPermissionUpdate {
				t.Fatal("terminal work became permission authority", err)
			}
			if _, err := ReadConnectorPermissionResult(bytes.NewReader(wire)); err != ErrConnectorPermissionUpdate {
				t.Fatal("terminal work became a renewal result", err)
			}
		})
	}
}

type connectorControlInvalidPayload struct {
	name    string
	payload string
}

func connectorControlInvalidPayloads(t *testing.T, payload string) []connectorControlInvalidPayload {
	t.Helper()
	invalid := []connectorControlInvalidPayload{
		{"null", "null"}, {"empty-object", "{}"}, {"array", "[]"}, {"empty-kind", `{"kind":""}`},
		{"trailing-object", payload + "{}"}, {"trailing-null", payload + "null"},
		{"unknown-field", strings.TrimSuffix(payload, "}") + `,"extra":true}`},
		{"invalid-utf8", strings.TrimSuffix(payload, "}") + ",\"extra\":\"\xff\"}"},
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &fields); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, mutation := range []string{"missing", "null", "wrong-case", "wrong-type"} {
			next := make(map[string]json.RawMessage, len(fields))
			for key, value := range fields {
				next[key] = value
			}
			switch mutation {
			case "missing":
				delete(next, name)
			case "null":
				next[name] = json.RawMessage("null")
			case "wrong-case":
				delete(next, name)
				next[strings.ToUpper(name[:1])+name[1:]] = fields[name]
			case "wrong-type":
				next[name] = json.RawMessage("[]")
			}
			body, err := json.Marshal(next)
			if err != nil {
				t.Fatal(err)
			}
			invalid = append(invalid, connectorControlInvalidPayload{mutation + "-" + name, string(body)})
		}
		key, err := json.Marshal(name)
		if err != nil {
			t.Fatal(err)
		}
		duplicate := strings.TrimSuffix(payload, "}") + "," + string(key) + ":" + string(fields[name]) + "}"
		invalid = append(invalid, connectorControlInvalidPayload{"duplicate-" + name, duplicate})
	}
	return invalid
}

func TestConnectorTerminalStrictFieldsAndSiblingIsolation(t *testing.T) {
	for _, fixture := range connectorTerminalWireFixtures() {
		for _, invalid := range connectorControlInvalidPayloads(t, fixture.payload) {
			t.Run(fixture.name+"/"+invalid.name, func(t *testing.T) {
				wire := append(connectorTerminalFrame(invalid.payload), connectorTerminalFrame(fixture.payload)...)
				reader := bytes.NewReader(wire)
				if got, err := readConnectorTerminalFixture(reader, fixture.message); err != ErrConnectorPermissionUpdate || got != nil {
					t.Fatal("invalid bounded payload was not an exact inert malformed leaf", got, err)
				}
				if got, err := readConnectorTerminalFixture(reader, fixture.message); err != nil || got != fixture.message || reader.Len() != 0 {
					t.Fatal("bad payload consumed or changed its valid sibling", got, err)
				}
			})
		}
	}
}

func TestConnectorTerminalClosedPurposesOutcomesAndNumbers(t *testing.T) {
	for _, fixture := range connectorTerminalWireFixtures() {
		invalid := []string{
			strings.Replace(fixture.payload, `"delivery_generation":7`, `"delivery_generation":0`, 1),
			strings.Replace(fixture.payload, `"delivery_generation":7`, `"delivery_generation":-1`, 1),
			strings.Replace(fixture.payload, `"delivery_generation":7`, `"delivery_generation":9223372036854775808`, 1),
			strings.Replace(fixture.payload, `"delivery_generation":7`, `"delivery_generation":"7"`, 1),
			strings.Replace(fixture.payload, `"delivery_generation":7`, `"delivery_generation":7.0`, 1),
			strings.Replace(fixture.payload, `"vc_aaaaaaaaaaaaaaaaaaaaaa"`, `"vc_invalid"`, 1),
			strings.Replace(fixture.payload, `"kind":"`, `"kind":"future_`, 1),
			strings.Replace(fixture.payload, `,"terminal_number":1`, "", 1),
		}
		for _, number := range []string{"0", "-1", "18446744073709551616", `"1"`, "1.0", "1e0"} {
			invalid = append(invalid, strings.Replace(fixture.payload, `"terminal_number":1`, `"terminal_number":`+number, 1))
		}
		if strings.Contains(fixture.payload, `"purpose"`) {
			invalid = append(invalid,
				strings.Replace(fixture.payload, `"purpose":"completion"`, `"purpose":""`, 1),
				strings.Replace(fixture.payload, `"purpose":"abort"`, `"purpose":"future"`, 1),
				strings.Replace(fixture.payload, `"outcome":"`, `"outcome":"future_`, 1),
			)
		}
		if _, observed := fixture.message.(ConnectorVisitorTerminalObserved); observed {
			outcome := fixture.message.(ConnectorVisitorTerminalObserved).Outcome
			invalid = append(invalid, strings.Replace(fixture.payload, `"outcome":"`+string(outcome)+`"`, `"outcome":"rejected"`, 1))
		}
		for _, payload := range invalid {
			if payload == fixture.payload {
				continue
			}
			if got, err := readConnectorTerminalFixture(bytes.NewReader(connectorTerminalFrame(payload)), fixture.message); err != ErrConnectorPermissionUpdate || got != nil {
				t.Fatal("terminal decoder accepted a noncanonical decision or identity", payload, got, err)
			}
		}
	}
}

func TestConnectorControlDirectionalBounds(t *testing.T) {
	for _, fixture := range connectorTerminalWireFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			padded := fixture.payload + strings.Repeat(" ", MaxConnectorTerminalBytes-len(fixture.payload))
			reader := bytes.NewReader(append(connectorTerminalFrame(padded), []byte("untouched")...))
			if got, err := readConnectorTerminalFixture(reader, fixture.message); err != nil || got != fixture.message || reader.Len() != len("untouched") {
				t.Fatal("exact terminal bound changed or consumed following bytes", got, err)
			}
			if _, reply := fixture.message.(ConnectorControlReply); !reply {
				reader := bytes.NewReader(append(connectorTerminalFrame(padded+" "), connectorTerminalFrame(fixture.payload)...))
				if got, err := ReadConnectorControlMessage(reader); err != ErrConnectorPermissionUpdate || got != nil {
					t.Fatal("terminal request borrowed the larger permission payload allowance", got, err)
				}
				if got, err := ReadConnectorControlMessage(reader); err != nil || got != fixture.message {
					t.Fatal("oversized bounded terminal payload consumed its sibling", got, err)
				}
			}
		})
	}
	for _, test := range []struct {
		limit int
		read  func(io.Reader) error
	}{
		{MaxConnectorPermissionBytes, func(r io.Reader) error { _, err := ReadConnectorControlMessage(r); return err }},
		{MaxConnectorTerminalBytes, func(r io.Reader) error { _, err := ReadConnectorControlReply(r); return err }},
		{256, func(r io.Reader) error { return ReadConnectorPermissionHello(r, false) }},
		{256, func(r io.Reader) error { return ReadConnectorPermissionHello(r, true) }},
	} {
		for _, size := range []uint32{0, uint32(test.limit + 1), math.MaxUint32} {
			reader := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32(nil, size))}
			if err := test.read(reader); err == nil || reader.payloadReads != 0 {
				t.Fatal("invalid length reached payload allocation or reading", size, err, reader.payloadReads)
			}
		}
	}
	var update bytes.Buffer
	if err := WriteConnectorPermissionUpdate(&update, permissionUpdateFixture()); err != nil {
		t.Fatal(err)
	}
	payload := string(update.Bytes()[4:])
	payload += strings.Repeat(" ", MaxConnectorPermissionBytes-len(payload))
	if got, err := ReadConnectorControlMessage(bytes.NewReader(connectorTerminalFrame(payload))); err != nil || got != permissionUpdateFixture() {
		t.Fatal("strict control decoding shrank the existing permission bound", got, err)
	}
}

func TestConnectorTerminalInvalidWritesProduceNoBytes(t *testing.T) {
	validAbort := ConnectorVisitorAbort{Kind: ConnectorVisitorAborted, VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7, TerminalNumber: 1}
	invalidAbortKind, invalidAbortVisitor, invalidAbortGeneration, invalidAbortNumber := validAbort, validAbort, validAbort, validAbort
	invalidAbortKind.Kind = ConnectorVisitorCompleted
	invalidAbortVisitor.VisitorConnectionID = "vc_invalid"
	invalidAbortGeneration.DeliveryGeneration = 0
	invalidAbortNumber.TerminalNumber = 0
	invalidCompletionNumber := ConnectorVisitorCompletion{Kind: ConnectorVisitorCompleted, VisitorConnectionID: validAbort.VisitorConnectionID, DeliveryGeneration: 7}
	result := connectorTerminalResultFixture(ConnectorTerminalCompletion, ConnectorTerminalAccepted)
	invalidResultKind, invalidResultVisitor, invalidResultGeneration, invalidResultPurpose, invalidResultOutcome, invalidResultNumber := result, result, result, result, result, result
	invalidResultKind.Kind = ConnectorVisitorTerminalObservedKind
	invalidResultVisitor.VisitorConnectionID = ""
	invalidResultGeneration.DeliveryGeneration = -1
	invalidResultPurpose.Purpose = "future"
	invalidResultOutcome.Outcome = "future"
	invalidResultNumber.TerminalNumber = 0
	observed := connectorTerminalObservedFixture(ConnectorTerminalAbort, ConnectorTerminalAccepted)
	invalidObservedKind, invalidObservedVisitor, invalidObservedGeneration, invalidObservedPurpose, invalidObservedOutcome, invalidObservedNumber := observed, observed, observed, observed, observed, observed
	invalidObservedKind.Kind = ConnectorVisitorTerminalResultKind
	invalidObservedVisitor.VisitorConnectionID = ""
	invalidObservedGeneration.DeliveryGeneration = 0
	invalidObservedPurpose.Purpose = ""
	invalidObservedOutcome.Outcome = "future"
	invalidObservedNumber.TerminalNumber = 0
	for _, invalid := range []any{
		invalidCompletionNumber,
		ConnectorVisitorAbort{}, invalidAbortKind, invalidAbortVisitor, invalidAbortGeneration, invalidAbortNumber,
		ConnectorVisitorTerminalResult{}, invalidResultKind, invalidResultVisitor, invalidResultGeneration, invalidResultPurpose, invalidResultOutcome, invalidResultNumber,
		ConnectorVisitorTerminalObserved{}, invalidObservedKind, invalidObservedVisitor, invalidObservedGeneration, invalidObservedPurpose, invalidObservedOutcome, invalidObservedNumber,
		connectorTerminalObservedFixture(ConnectorTerminalCompletion, ConnectorTerminalRejected),
		connectorTerminalObservedFixture(ConnectorTerminalAbort, ConnectorTerminalRejected),
	} {
		var wire bytes.Buffer
		if err := writeConnectorTerminalFixture(&wire, invalid); err != ErrConnectorPermissionUpdate || wire.Len() != 0 {
			t.Fatal("invalid terminal decision emitted bytes", invalid, err)
		}
	}
}

func TestConnectorTerminalWritersPreserveIOFailures(t *testing.T) {
	independent := errors.New("independent terminal write failure")
	for _, fixture := range connectorTerminalWireFixtures() {
		for _, failAt := range []int{1, 2} {
			for _, short := range []bool{false, true} {
				writer := &failingWriter{failAt: failAt, failure: independent, short: short}
				want := independent
				if short {
					want = io.ErrShortWrite
				}
				if err := writeConnectorTerminalFixture(writer, fixture.message); !errors.Is(err, want) || writer.call != failAt {
					t.Fatal("terminal framing lost a write failure or retried after it", fixture.name, err, writer.call)
				}
			}
		}
	}
}

func TestConnectorTerminalCheckedScopeAndOriginalKey(t *testing.T) {
	scope := ConnectorControlScope{
		ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", ServiceRunID: "srun_aaaaaaaaaaaaaaaaaaaaaa", RunNumber: 1,
		PublisherIdentityID: "pub_aaaaaaaaaaaaaaaaaaaaaa", PairID: "cpp_aaaaaaaaaaaaaaaaaaaaaa",
	}
	if err := scope.Validate(); err != nil {
		t.Fatal("valid fixed scope rejected", err)
	}
	for _, change := range []func(*ConnectorControlScope){
		func(s *ConnectorControlScope) { s.ServiceID = "" },
		func(s *ConnectorControlScope) { s.ServiceRunID = s.ServiceID },
		func(s *ConnectorControlScope) { s.RunNumber = 0 },
		func(s *ConnectorControlScope) { s.RunNumber = uint64(math.MaxInt64) + 1 },
		func(s *ConnectorControlScope) { s.PublisherIdentityID = s.PairID },
		func(s *ConnectorControlScope) { s.PairID = s.PublisherIdentityID },
	} {
		invalid := scope
		change(&invalid)
		if err := invalid.Validate(); err != ErrConnectorPermissionUpdate {
			t.Fatal("invalid fixed scope accepted", invalid, err)
		}
	}
	key := ConnectorVisitorTerminalKey{VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: math.MaxInt64}
	if err := key.Validate(); err != nil {
		t.Fatal("maximum original generation rejected", err)
	}
	for _, invalid := range []ConnectorVisitorTerminalKey{
		{}, {VisitorConnectionID: key.VisitorConnectionID}, {VisitorConnectionID: key.VisitorConnectionID, DeliveryGeneration: -1},
		{VisitorConnectionID: "vc_invalid", DeliveryGeneration: 7},
	} {
		if err := invalid.Validate(); err != ErrConnectorPermissionUpdate {
			t.Fatal("invalid terminal key accepted", invalid, err)
		}
	}
	for _, fixture := range connectorTerminalWireFixtures() {
		request := fixture.message.(interface {
			TerminalRequest() ConnectorVisitorTerminalRequest
		}).TerminalRequest()
		if request.Validate() != nil || request.Key.VisitorConnectionID != "vc_aaaaaaaaaaaaaaaaaaaaaa" || request.Key.DeliveryGeneration != 7 || request.TerminalNumber != 1 {
			t.Fatal("normalization lost the opening's original identity or terminal number", request)
		}
		if fixture.name == "completion" && request.Purpose != ConnectorTerminalCompletion ||
			fixture.name == "abort" && request.Purpose != ConnectorTerminalAbort {
			t.Fatal("a completion became abort or abort became completion", request)
		}
	}
	for _, purpose := range []ConnectorTerminalPurpose{"", "future"} {
		if err := (ConnectorVisitorTerminalRequest{Key: key, Purpose: purpose, TerminalNumber: 1}).Validate(); err != ErrConnectorPermissionUpdate {
			t.Fatal("normalized request accepted an open purpose", err)
		}
	}
	if err := (ConnectorVisitorTerminalRequest{Key: key, Purpose: ConnectorTerminalCompletion}).Validate(); err != ErrConnectorPermissionUpdate {
		t.Fatal("normalized request accepted a missing terminal number", err)
	}
	if err := (ConnectorVisitorTerminalRequest{Key: key, Purpose: ConnectorTerminalAbort, TerminalNumber: math.MaxUint64}).Validate(); err != nil {
		t.Fatal("normalized request rejected the maximum terminal number", err)
	}
}

func TestConnectorControlReadersPreserveIndependentIOFailures(t *testing.T) {
	independent := errors.New("independent control read failure")
	cause := errors.Join(io.EOF, ErrConnectorPermissionUpdate, independent)
	for _, read := range []func(io.Reader) error{
		func(r io.Reader) error { _, err := ReadConnectorControlMessage(r); return err },
		func(r io.Reader) error { _, err := ReadConnectorControlReply(r); return err },
		func(r io.Reader) error { _, err := ReadConnectorPermissionResult(r); return err },
		func(r io.Reader) error { _, err := ReadConnectorPermissionUpdate(r); return err },
		func(r io.Reader) error { return ReadConnectorPermissionHello(r, false) },
	} {
		reader := io.MultiReader(bytes.NewReader(binary.BigEndian.AppendUint32(nil, 2)), frameReadFailure{err: cause})
		if err := read(reader); err == ErrConnectorPermissionUpdate || !errors.Is(err, independent) || !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, ErrConnectorPermissionUpdate) {
			t.Fatal("framing failure was reduced to a skippable malformed leaf", err)
		}
	}
}

func FuzzConnectorControlReply(f *testing.F) {
	for _, fixture := range append(connectorTerminalWireFixtures(), connectorTerminalMaximumWireFixtures()...) {
		f.Add(connectorTerminalFrame(fixture.payload))
	}
	for _, kind := range []StreamKind{ConnectorPermissionAccepted, ConnectorPermissionRejected, ConnectorPermissionStale} {
		var wire bytes.Buffer
		_ = WriteConnectorPermissionResult(&wire, ConnectorPermissionResult{
			VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 7, UpdateNumber: 1, Kind: kind,
		})
		f.Add(wire.Bytes())
	}
	f.Add([]byte{0, 0, 0, 1, '{'})
	f.Fuzz(func(t *testing.T, wire []byte) {
		reply, err := ReadConnectorControlReply(bytes.NewReader(wire))
		if err != nil {
			return
		}
		var out bytes.Buffer
		switch reply := reply.(type) {
		case ConnectorPermissionResult:
			err = WriteConnectorPermissionResult(&out, reply)
		case ConnectorVisitorTerminalResult:
			err = WriteConnectorVisitorTerminalResult(&out, reply)
		default:
			t.Fatal("unknown typed control reply")
		}
		if err != nil {
			t.Fatal("accepted reply could not be written", err)
		}
		if got, err := ReadConnectorControlReply(&out); err != nil || got != reply {
			t.Fatal("reply lost its exact binding on round-trip", got, err)
		}
	})
}
