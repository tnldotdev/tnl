package controlv1

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestDecimalCounters(t *testing.T) {
	for _, value := range []int64{0, 1, 9007199254740991, 9007199254740993, math.MaxInt64} {
		request := ApplyProjectConfigurationRequest{ExpectedRevision: value}
		data, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		var decimal string
		if err = json.Unmarshal(fields["expected_revision"], &decimal); err != nil || decimal == "" {
			t.Fatalf("revision was not a JSON string: %s (%v)", data, err)
		}
		var decoded ApplyProjectConfigurationRequest
		if err = json.Unmarshal(data, &decoded); err != nil || decoded.ExpectedRevision != value {
			t.Fatalf("revision changed on round trip: %s (%v)", data, err)
		}
	}
}

func TestDecimalCountersRejectNumericAndOutOfRangeInput(t *testing.T) {
	for _, value := range []string{`9007199254740993`, `"9223372036854775808"`, `"1.5"`, `"1e3"`, `""`} {
		var request ApplyProjectConfigurationRequest
		if err := json.Unmarshal([]byte(`{"expected_revision":`+value+`}`), &request); err == nil {
			t.Fatalf("accepted revision %s", value)
		}
	}
}

func TestDecimalRevisionList(t *testing.T) {
	want := RevisionList{1, 9007199254740993, math.MaxInt64}
	data, err := json.Marshal(want)
	if err != nil || string(data) != `["1","9007199254740993","9223372036854775807"]` {
		t.Fatalf("revision list: %s (%v)", data, err)
	}
	var got RevisionList
	if err = json.Unmarshal(data, &got); err != nil || len(got) != len(want) {
		t.Fatal("decode revisions", got, err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal("revision changed", got)
		}
	}
	for _, invalid := range []string{`[1]`, `["9223372036854775808"]`, `["1.5"]`, `[null]`} {
		if err := json.Unmarshal([]byte(invalid), &got); err == nil {
			t.Fatalf("accepted revisions %s", invalid)
		}
	}
}

func TestRunNumberIsStringAndPortIsNumber(t *testing.T) {
	data, err := json.Marshal(ServiceRunSetup{RunNumber: 9007199254740993})
	if err != nil || !strings.Contains(string(data), `"run_number":"9007199254740993"`) {
		t.Fatalf("run number: %s (%v)", data, err)
	}
	data, err = json.Marshal(AppliedProjectService{Port: new(65535)})
	if err != nil || !strings.Contains(string(data), `"port":65535`) {
		t.Fatalf("port: %s (%v)", data, err)
	}
}
