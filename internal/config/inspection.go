package config

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
	"go.yaml.in/yaml/v3"
)

// InspectionMode selects whether local observations are recorded.
type InspectionMode string

const (
	InspectionNone    InspectionMode = "none"
	InspectionSummary InspectionMode = "summary"
)

func (mode InspectionMode) Valid() bool {
	return mode == InspectionNone || mode == InspectionSummary
}

// Inspection provides project defaults and optional service-level overrides.
type Inspection struct {
	Mode      *InspectionMode `json:"mode,omitempty" yaml:"mode,omitempty" jsonschema:"enum=none,enum=summary"`
	Retention *Duration       `json:"retention,omitempty" yaml:"retention,omitempty"`
	MaxBytes  *ByteSize       `json:"max_bytes,omitempty" yaml:"max_bytes,omitempty"`
}

func MergeInspection(base, override *Inspection) *Inspection {
	if base == nil && override == nil {
		return nil
	}
	result := &Inspection{}
	if base != nil {
		*result = *base
	}
	if override != nil {
		if override.Mode != nil {
			result.Mode = override.Mode
		}
		if override.Retention != nil {
			result.Retention = override.Retention
		}
		if override.MaxBytes != nil {
			result.MaxBytes = override.MaxBytes
		}
	}
	return result
}

// ByteSize accepts a whole number of KiB, MiB, or GiB.
type ByteSize int64

func (size ByteSize) Value() int64 { return int64(size) }

func ParseByteSize(value string) (ByteSize, error) {
	for _, unit := range []struct {
		suffix string
		bytes  int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}} {
		if !strings.HasSuffix(value, unit.suffix) {
			continue
		}
		count, err := strconv.ParseInt(strings.TrimSuffix(value, unit.suffix), 10, 64)
		if err != nil || count < 1 || count > inspection.MaxMaxBytes/unit.bytes {
			return 0, errors.New("max_bytes must be between 1MiB and 1GiB")
		}
		bytes := count * unit.bytes
		if bytes < inspection.MinMaxBytes {
			return 0, errors.New("max_bytes must be between 1MiB and 1GiB")
		}
		return ByteSize(bytes), nil
	}
	return 0, errors.New("max_bytes must use KiB, MiB, or GiB")
}

func (size *ByteSize) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return errors.New("max_bytes must be a string")
	}
	parsed, err := ParseByteSize(value)
	if err != nil {
		return err
	}
	*size = parsed
	return nil
}

func (size *ByteSize) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return errors.New("max_bytes must be a string")
	}
	parsed, err := ParseByteSize(node.Value)
	if err != nil {
		return err
	}
	*size = parsed
	return nil
}

func ValidateInspection(value *Inspection) error {
	if value == nil {
		return nil
	}
	if value.Mode != nil && !value.Mode.Valid() {
		return errors.New("mode must be none or summary")
	}
	if value.Retention != nil && (value.Retention.Value() < time.Minute || value.Retention.Value() > inspection.MaxRetention) {
		return fmt.Errorf("retention must be between 1m and %dh", int(inspection.MaxRetention/time.Hour))
	}
	if value.MaxBytes != nil && (value.MaxBytes.Value() < inspection.MinMaxBytes || value.MaxBytes.Value() > inspection.MaxMaxBytes) {
		return errors.New("max_bytes must be between 1MiB and 1GiB")
	}
	return nil
}
