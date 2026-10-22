package serviceaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// Destination is resolved for every attempt. ingress reporters must provide the
// exact lease query parameters captured for their queue's source, not relabel
// observations from a previous process run as a newly acquired lease.
type Destination struct {
	URL              string
	Bearer           string
	PublishRunNumber int64
}

// HTTPReporter uses the normal API authentication on bounded background batches.
// errors deliberately omit URL, bearer, response bodies and request contents.
func HTTPReporter(client *http.Client, destination func(context.Context) (Destination, error)) Reporter {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context, batch Batch) error {
		d, err := destination(ctx)
		if err != nil {
			return errors.New("service audit destination unavailable")
		}
		var payload any = batch
		if d.PublishRunNumber > 0 {
			payload = struct {
				Events           []Observation `json:"events"`
				PublishRunNumber int64         `json:"publish_run_number"`
			}{batch.Events, d.PublishRunNumber}
		}
		encoded, err := json.Marshal(payload)
		if err != nil || len(encoded) > MaxPayloadBytes {
			return errors.Join(ErrRejected, ErrInvalid)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(encoded))
		if err != nil {
			return errors.New("invalid service audit destination")
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+d.Bearer)
		response, err := client.Do(request)
		if err != nil {
			return errors.New("service audit request failed")
		}
		defer response.Body.Close()
		switch response.StatusCode {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusGone, http.StatusRequestEntityTooLarge:
			return ErrRejected
		}
		if response.StatusCode != http.StatusOK {
			return errors.New("service audit batch was not accepted")
		}
		var acknowledgement struct {
			Accepted   int `json:"accepted"`
			Duplicates int `json:"duplicates"`
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&acknowledgement) != nil || decoder.Decode(new(any)) != io.EOF {
			return errors.New("invalid service audit acknowledgement")
		}
		return ValidateAcknowledgement(acknowledgement.Accepted, acknowledgement.Duplicates, len(batch.Events))
	}
}
