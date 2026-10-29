package telemetryv1

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const MaximumBatchBytes = 64 << 10
const MaximumEventBytes = 8 << 10

var ErrInvalid = errors.New("telemetry data does not match the v1 contract")

//go:embed validation.gen.json
var validationDocument []byte

// validation reads only the generated contract's bounded schema vocabulary.
// no network references or user-provided schemas enter this owner.
type schema struct {
	Ref                   string            `json:"$ref"`
	Type                  string            `json:"type"`
	Enum                  []json.RawMessage `json:"enum"`
	Properties            map[string]schema `json:"properties"`
	Required              []string          `json:"required"`
	AdditionalProperties  *bool             `json:"additionalProperties"`
	UnevaluatedProperties *bool             `json:"unevaluatedProperties"`
	AllOf                 []schema          `json:"allOf"`
	OneOf                 []schema          `json:"oneOf"`
	Items                 *schema           `json:"items"`
	Minimum               *int64            `json:"minimum"`
	Maximum               *int64            `json:"maximum"`
	MinItems              *int              `json:"minItems"`
	MaxItems              *int              `json:"maxItems"`
	MinLength             *int              `json:"minLength"`
	MaxLength             *int              `json:"maxLength"`
	Pattern               string            `json:"pattern"`
}

var validationSchemas = func() map[string]schema {
	var document struct {
		Components struct {
			Schemas map[string]schema `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(validationDocument, &document) != nil || len(document.Components.Schemas) == 0 {
		panic("generated telemetry contract is invalid")
	}
	var source struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(validationDocument, &source) != nil || len(source.Components.Schemas) != len(document.Components.Schemas) {
		panic("generated telemetry schema source is invalid")
	}
	for name, raw := range source.Components.Schemas {
		if err := checkVocabulary(raw); err != nil {
			panic(fmt.Sprintf("telemetry schema %s: %v", name, err))
		}
	}
	return document.Components.Schemas
}()

// Reject a new assertion keyword until native validation supports it. The
// generated contract is trusted source, but silently ignoring a new keyword
// would let native and website acceptance diverge.
func checkVocabulary(raw json.RawMessage) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return ErrInvalid
	}
	for key, value := range fields {
		switch key {
		case "$ref", "type", "enum", "required", "additionalProperties", "unevaluatedProperties",
			"minimum", "maximum", "minItems", "maxItems", "minLength", "maxLength", "pattern",
			"description", "discriminator", "x-enum-varnames", "x-tnl-upper-bounds-ms":
		case "format":
			if string(value) != `"int64"` {
				return ErrInvalid
			}
		case "properties":
			var properties map[string]json.RawMessage
			if json.Unmarshal(value, &properties) != nil || properties == nil {
				return ErrInvalid
			}
			for _, nested := range properties {
				if err := checkVocabulary(nested); err != nil {
					return err
				}
			}
		case "items":
			if err := checkVocabulary(value); err != nil {
				return err
			}
		case "allOf", "oneOf":
			var parts []json.RawMessage
			if json.Unmarshal(value, &parts) != nil || len(parts) == 0 {
				return ErrInvalid
			}
			for _, part := range parts {
				if err := checkVocabulary(part); err != nil {
					return err
				}
			}
		default:
			return ErrInvalid
		}
	}
	return nil
}

func ValidateBatch(data []byte) error {
	if err := validateJSON(data, "Batch", MaximumBatchBytes); err != nil {
		return err
	}
	var batch struct {
		Events []json.RawMessage `json:"events"`
	}
	if json.Unmarshal(data, &batch) != nil {
		return ErrInvalid
	}
	seen := make(map[string]bool, len(batch.Events))
	for _, event := range batch.Events {
		if err := ValidateEvent(event); err != nil {
			return err
		}
		var header struct {
			ID string `json:"event_id"`
		}
		if json.Unmarshal(event, &header) != nil || seen[header.ID] {
			return ErrInvalid
		}
		seen[header.ID] = true
	}
	return nil
}

func ValidateEvent(data []byte) error {
	if err := validateJSON(data, "Event", MaximumEventBytes); err != nil {
		return err
	}
	var event struct {
		Name    string          `json:"name"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(data, &event) != nil {
		return ErrInvalid
	}
	switch event.Name {
	case "command.outcome":
		var outcome CommandOutcome
		if json.Unmarshal(event.Payload, &outcome) != nil ||
			(outcome.Outcome == Failed) != (outcome.FailureStage != nil) {
			return ErrInvalid
		}
	case "integration.outcome":
		var outcome IntegrationOutcome
		if json.Unmarshal(event.Payload, &outcome) != nil ||
			outcome.Kind == Oauth && (outcome.Outcome == ReachedReceiver || outcome.Delivery != nil) ||
			outcome.Kind == Webhook && (outcome.Outcome == Redirected || outcome.Outcome == ReachedReceiver && outcome.Delivery == nil) {
			return ErrInvalid
		}
	case "publisher.report":
		var report PublisherReport
		if json.Unmarshal(event.Payload, &report) != nil {
			return ErrInvalid
		}
		switch kind, err := report.Discriminator(); {
		case err != nil:
			return ErrInvalid
		case kind == "public_ingress":
			public, err := report.AsPublicReport()
			if err != nil || !distinctPublicPaths(public.Paths) || !distinctFallbacks(public.Fallbacks) {
				return ErrInvalid
			}
			for _, path := range public.Paths {
				if !validHistogram(path.Rtt) {
					return ErrInvalid
				}
			}
		case kind == "native_peer":
			native, err := report.AsNativeReport()
			if err != nil || !distinctNativePaths(native.Paths) || !distinctFallbacks(native.Fallbacks) || !validHistogram(native.DirectEstablishment) {
				return ErrInvalid
			}
			for _, path := range native.Paths {
				if !validHistogram(path.Rtt) {
					return ErrInvalid
				}
			}
			if native.DirectSetupSuccesses != nil && (native.DirectSetupAttempts == nil || *native.DirectSetupSuccesses > *native.DirectSetupAttempts) ||
				native.DirectEstablishment != nil && (native.DirectSetupSuccesses == nil || histogramTotal(native.DirectEstablishment) > *native.DirectSetupSuccesses) {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	return nil
}

func distinctPublicPaths(paths []PublicPathAggregate) bool {
	seen := make(map[PublicPathAggregatePath]bool, len(paths))
	for _, path := range paths {
		if seen[path.Path] {
			return false
		}
		seen[path.Path] = true
	}
	return true
}

func distinctNativePaths(paths []NativePathAggregate) bool {
	seen := make(map[NativePathAggregatePath]bool, len(paths))
	for _, path := range paths {
		if seen[path.Path] {
			return false
		}
		seen[path.Path] = true
	}
	return true
}

func distinctFallbacks(fallbacks *[]FallbackCount) bool {
	if fallbacks == nil {
		return true
	}
	seen := make(map[FallbackCountReason]bool, len(*fallbacks))
	for _, fallback := range *fallbacks {
		if seen[fallback.Reason] {
			return false
		}
		seen[fallback.Reason] = true
	}
	return true
}

func validHistogram(histogram *Histogram) bool {
	if histogram == nil {
		return true
	}
	var total int64
	for _, count := range *histogram {
		total += count
		if total > 1_000_000_000 {
			return false
		}
	}
	return true
}

func histogramTotal(histogram *Histogram) int64 {
	var total int64
	for _, count := range *histogram {
		total += count
	}
	return total
}

func ValidateClient(data []byte) error { return validateJSON(data, "Client", 512) }

func validateJSON(data []byte, name string, limit int) error {
	if len(data) == 0 || len(data) > limit || !utf8.Valid(data) || !json.Valid(data) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	definition, found := validationSchemas[name]
	if !found || decoder.Decode(&value) != nil || !definition.valid(value, 0) {
		return ErrInvalid
	}
	return nil
}

func (s schema) valid(value any, depth int) bool {
	if depth > 32 {
		return false
	}
	if s.Ref != "" {
		name, local := strings.CutPrefix(s.Ref, "#/components/schemas/")
		referenced, found := validationSchemas[name]
		return local && found && referenced.valid(value, depth+1)
	}
	for _, part := range s.AllOf {
		if !part.valid(value, depth+1) {
			return false
		}
	}
	if len(s.OneOf) > 0 {
		matches := 0
		for _, part := range s.OneOf {
			if part.valid(value, depth+1) {
				matches++
			}
		}
		if matches != 1 {
			return false
		}
	}
	if len(s.Enum) > 0 {
		encoded, err := json.Marshal(value)
		if err != nil {
			return false
		}
		found := false
		for _, option := range s.Enum {
			found = found || bytes.Equal(encoded, option)
		}
		if !found {
			return false
		}
	}
	switch s.Type {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		for _, key := range s.Required {
			if _, present := object[key]; !present {
				return false
			}
		}
		for key, definition := range s.Properties {
			if item, present := object[key]; present && !definition.valid(item, depth+1) {
				return false
			}
		}
	case "array":
		items, ok := value.([]any)
		if !ok || s.Items == nil || s.MinItems != nil && len(items) < *s.MinItems || s.MaxItems != nil && len(items) > *s.MaxItems {
			return false
		}
		for _, item := range items {
			if !s.Items.valid(item, depth+1) {
				return false
			}
		}
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		integer, err := number.Int64()
		if err != nil || s.Minimum != nil && integer < *s.Minimum || s.Maximum != nil && integer > *s.Maximum {
			return false
		}
	case "string":
		text, ok := value.(string)
		if !ok {
			return false
		}
		length := utf8.RuneCountInString(text)
		if s.MinLength != nil && length < *s.MinLength || s.MaxLength != nil && length > *s.MaxLength {
			return false
		}
		if s.Pattern != "" && !regexp.MustCompile(s.Pattern).MatchString(text) {
			return false
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return false
		}
	case "":
	default:
		return false
	}
	if s.AdditionalProperties != nil && !*s.AdditionalProperties || s.UnevaluatedProperties != nil && !*s.UnevaluatedProperties {
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		allowed := make(map[string]struct{})
		if !s.properties(allowed, 0) {
			return false
		}
		for key := range object {
			if _, ok := allowed[key]; !ok {
				return false
			}
		}
	}
	return true
}

func (s schema) properties(keys map[string]struct{}, depth int) bool {
	if depth > 32 {
		return false
	}
	if s.Ref != "" {
		name, local := strings.CutPrefix(s.Ref, "#/components/schemas/")
		referenced, found := validationSchemas[name]
		return local && found && referenced.properties(keys, depth+1)
	}
	for key := range s.Properties {
		keys[key] = struct{}{}
	}
	for _, part := range s.AllOf {
		if !part.properties(keys, depth+1) {
			return false
		}
	}
	return true
}
