package config

import (
	"errors"
)

// InspectionMode selects how much local observation detail to retain.
type InspectionMode string

const (
	InspectionSummary  InspectionMode = "summary"
	InspectionDetailed InspectionMode = "detailed"
)

func (mode InspectionMode) Valid() bool {
	return mode == InspectionSummary || mode == InspectionDetailed
}

// Inspection provides project defaults and optional service-level overrides.
type Inspection struct {
	Mode *InspectionMode `json:"mode,omitempty" yaml:"mode,omitempty" jsonschema:"enum=summary,enum=detailed"`
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
		return errors.New("mode must be summary or detailed")
	}
	return nil
}
