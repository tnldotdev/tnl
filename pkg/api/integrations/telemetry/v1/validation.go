package telemetryv1

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const MaximumBatchBytes = 64 << 10
const MaximumEventBytes = 16 << 10

var ErrInvalid = errors.New("telemetry does not match the v1 contract")

//go:embed validation.gen.json
var document []byte

var schemas = func() map[string]*jsonschema.Schema {
	var source any
	if err := json.Unmarshal(document, &source); err != nil {
		panic(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("urn:tnl:telemetry", source); err != nil {
		panic(err)
	}
	result := map[string]*jsonschema.Schema{}
	for _, name := range []string{"Batch", "Event", "Client"} {
		definition, err := compiler.Compile("urn:tnl:telemetry#/components/schemas/" + name)
		if err != nil {
			panic(err)
		}
		result[name] = definition
	}
	return result
}()

func validate(data []byte, name string, limit int) error {
	if len(data) == 0 || len(data) > limit || !utf8.Valid(data) || !json.Valid(data) {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil || schemas[name].Validate(value) != nil {
		return ErrInvalid
	}
	return nil
}

func ValidateClient(data []byte) error { return validate(data, "Client", 512) }
func ValidateEvent(data []byte) error  { return validate(data, "Event", MaximumEventBytes) }
func ValidateBatch(data []byte) error {
	if err := validate(data, "Batch", MaximumBatchBytes); err != nil {
		return err
	}
	var batch struct {
		Events []json.RawMessage `json:"events"`
	}
	if json.Unmarshal(data, &batch) != nil {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, event := range batch.Events {
		if ValidateEvent(event) != nil {
			return ErrInvalid
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
