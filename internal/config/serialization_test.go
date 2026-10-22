package config

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"strconv"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestInspectionSerializationRoundTrip(t *testing.T) {
	for _, size := range []ByteSize{1 << 20, 64 << 20, 1025 << 10, 1 << 30} {
		for _, codec := range []struct {
			name      string
			marshal   func(any) ([]byte, error)
			unmarshal func([]byte, any) error
		}{
			{"json", json.Marshal, json.Unmarshal},
			{"json-v2", func(v any) ([]byte, error) { return jsonv2.Marshal(v) }, func(b []byte, v any) error { return jsonv2.Unmarshal(b, v) }},
			{"yaml", yaml.Marshal, yaml.Unmarshal},
		} {
			t.Run(codec.name+"/"+strconv.FormatInt(size.Value(), 10), func(t *testing.T) {
				original := Inspection{MaxBytes: &size}
				encoded, err := codec.marshal(original)
				if err != nil {
					t.Fatal(err)
				}
				var restored Inspection
				if err := codec.unmarshal(encoded, &restored); err != nil {
					t.Fatalf("round trip %s: %v", encoded, err)
				}
				if restored.MaxBytes == nil || *restored.MaxBytes != size {
					t.Fatalf("round trip changed byte size: %s", encoded)
				}
			})
		}
	}
}

func TestInspectionSerializationRejectsUnrepresentableSizes(t *testing.T) {
	for _, size := range []ByteSize{0, 1<<20 - 1, 1<<20 + 1, 1<<30 + 1} {
		value := Inspection{MaxBytes: &size}
		if err := ValidateInspection(&value); err == nil {
			t.Fatalf("nonportable byte size validated: %d", size)
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatalf("nonportable JSON byte size encoded: %d", size)
		}
		if _, err := yaml.Marshal(value); err == nil {
			t.Fatalf("nonportable YAML byte size encoded: %d", size)
		}
	}
	for _, source := range []string{`{"max_bytes":67108864}`, `{"max_bytes":"1.5MiB"}`, `{"max_bytes":"65536"}`} {
		var value Inspection
		if err := json.Unmarshal([]byte(source), &value); err == nil {
			t.Fatalf("invalid config input accepted: %s", source)
		}
	}
}
