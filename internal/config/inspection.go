package config

import (
	json "encoding/json/v2"
	"errors"
	"regexp"
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

// ResolveInspection supplies bounded native retention settings.
func ResolveInspection(value *Inspection, protocol string) (inspection.Policy, error) {
	if !ValidProtocol(protocol) {
		return inspection.Policy{}, errors.New("unsupported service protocol")
	}
	if err := ValidateInspection(value); err != nil {
		return inspection.Policy{}, err
	}
	result := inspection.Policy{Mode: inspection.SummaryMode, Retention: inspection.DefaultRetention, MaxBytes: inspection.DefaultMaxBytes}
	if value != nil {
		if value.Mode != nil {
			result.Mode = inspection.Mode(*value.Mode)
		}
		if value.Retention != nil {
			result.Retention = value.Retention.Value()
		}
		if value.MaxBytes != nil {
			result.MaxBytes = value.MaxBytes.Value()
		}
	}
	return result, nil
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

func ValidateInspection(value *Inspection) error {
	if value == nil {
		return nil
	}
	if value.Mode != nil && !value.Mode.Valid() {
		return errors.New("mode must be none or summary")
	}
	if value.Retention != nil && (value.Retention.Value() < time.Minute || value.Retention.Value() > 30*24*time.Hour) {
		return errors.New("retention must be between 1m and 720h")
	}
	if value.MaxBytes != nil && (value.MaxBytes.Value() < 1<<20 || value.MaxBytes.Value() > 1<<30) {
		return errors.New("max_bytes must be between 1MiB and 1GiB")
	}
	return nil
}

type ByteSize int64

func (size ByteSize) Value() int64 { return int64(size) }

var byteSizeSyntax = regexp.MustCompile(`^[1-9][0-9]*(KiB|MiB|GiB)$`)

func ParseByteSize(value string) (ByteSize, error) {
	if !byteSizeSyntax.MatchString(value) {
		return 0, errors.New("max_bytes must be a positive whole KiB, MiB, or GiB size")
	}
	multiplier := int64(1 << 10)
	if strings.HasSuffix(value, "MiB") {
		multiplier = 1 << 20
	}
	if strings.HasSuffix(value, "GiB") {
		multiplier = 1 << 30
	}
	n, err := strconv.ParseInt(value[:len(value)-3], 10, 64)
	if err != nil || n > (1<<30)/multiplier || n*multiplier < 1<<20 {
		return 0, errors.New("max_bytes must be between 1MiB and 1GiB")
	}
	return ByteSize(n * multiplier), nil
}

func (size *ByteSize) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return errors.New("max_bytes must be a string")
	}
	value, err := ParseByteSize(text)
	if err == nil {
		*size = value
	}
	return err
}

func (size *ByteSize) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return errors.New("max_bytes must be a string")
	}
	value, err := ParseByteSize(node.Value)
	if err == nil {
		*size = value
	}
	return err
}
