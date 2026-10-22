package inspection

import (
	"encoding/json"
	"testing"
)

func TestProtocolParsingClassificationAndJSON(t *testing.T) {
	for _, tc := range []struct {
		value    string
		tcp, sql bool
	}{
		{"http", false, false}, {"postgres", true, true}, {"mysql", true, true}, {"redis", true, false},
	} {
		protocol, ok := ParseProtocol(tc.value)
		if !ok || string(protocol) != tc.value || protocol.IsSQL() != tc.sql || protocol.IsTCP() != tc.tcp {
			t.Fatalf("protocol %q = %q, %t", tc.value, protocol, ok)
		}
		data, err := json.Marshal(protocol)
		if err != nil || string(data) != `"`+tc.value+`"` {
			t.Fatalf("protocol JSON = %s, %v", data, err)
		}
		var decoded Protocol
		if err := json.Unmarshal(data, &decoded); err != nil || decoded != protocol {
			t.Fatalf("protocol JSON roundtrip = %q, %v", decoded, err)
		}
	}
	for _, value := range []string{"", "tcp", "kubernetes", "HTTP", "postgresql", " redis"} {
		protocol, ok := ParseProtocol(value)
		if ok || protocol.Valid() || protocol.IsSQL() || protocol.IsTCP() {
			t.Fatalf("classified unsupported inspection protocol %q", value)
		}
	}
}
