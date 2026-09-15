// Package httpjson shares bounded JSON mechanics, not API policy. Callers own
// authentication, media-type checks, timeouts, body closure, and problem/error
// classification. No generated API or domain types belong here.
package httpjson

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
)

var (
	ErrTooLarge        = errors.New("JSON body exceeds limit")
	ErrTrailingContent = errors.New("JSON contains trailing content")
)

// ReadAll reads at most limit+1 bytes to distinguish a full body from truncation.
// It never closes the reader. Size violations are distinct from I/O failures.
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

// Decode accepts one JSON value with no unknown struct fields or trailing data.
// Configure number handling and bound the input before calling. Standard JSON
// semantics for null and duplicate object keys are unchanged.
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

// Write emits application/json. Encoding failure aborts the HTTP response rather
// than appending another error after headers or a partial body have been sent.
func Write(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		panic(http.ErrAbortHandler)
	}
}
