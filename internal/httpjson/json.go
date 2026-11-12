// Package httpjson reads and writes size-limited JSON. callers handle
// authentication, media types, timeouts, closing bodies, and API errors. this
// package does not contain generated API or domain types.
package httpjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
)

var (
	ErrTooLarge        = errors.New("JSON body exceeds limit")
	ErrTrailingContent = errors.New("JSON contains trailing content")
	ErrNull            = errors.New("JSON contains null")
	ErrRequiredField   = errors.New("JSON object is missing a required field")
)

// ReadAll reads up to limit bytes and returns ErrTooLarge when more data exists.
// it does not close the reader. I/O failures are returned unchanged.
func ReadAll(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 0 || limit == math.MaxInt64 {
		return nil, errors.New("httpjson: invalid body limit")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, ErrTooLarge
	}
	return payload, nil
}

// Decode reads one JSON value and rejects unknown struct fields or trailing data.
// configure number handling and limit the input before calling it. the standard
// handling of null and duplicate object keys is unchanged.
func Decode(decoder *json.Decoder, destination any) error {
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrTrailingContent
	}
	return nil
}

// DecodeNonNullObject reads a request without losing omitted-vs-null fields in Go
// pointers or scalar zero values. required names come from the serving contract;
// unknown fields and trailing values retain Decode's normal rejection.
func DecodeNonNullObject(payload []byte, destination any, required ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	for {
		value, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if value == nil {
			return ErrNull
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return err
	}
	if fields == nil {
		return ErrRequiredField
	}
	for _, name := range required {
		if _, found := fields[name]; !found {
			return ErrRequiredField
		}
	}
	return Decode(json.NewDecoder(bytes.NewReader(payload)), destination)
}

// Write sends an application/json response. if encoding fails after writing has
// started, it aborts the response instead of adding a second error body.
func Write(response http.ResponseWriter, status int, value any) {
	write(response, status, "application/json", value)
}

// WriteProblem sends an application/problem+json response.
func WriteProblem(response http.ResponseWriter, status int, value any) {
	write(response, status, "application/problem+json", value)
}

func write(response http.ResponseWriter, status int, contentType string, value any) {
	response.Header().Set("Content-Type", contentType)
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		panic(http.ErrAbortHandler)
	}
}
