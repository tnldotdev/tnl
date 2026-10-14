package config

import (
	"errors"
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
	Mode *InspectionMode `json:"mode,omitempty" yaml:"mode,omitempty" jsonschema:"enum=none,enum=summary"`
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
	return nil
}
