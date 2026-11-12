package public

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/httpjson"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const environmentPublisherGrantBodyLimit int64 = 8 << 10

var errEnvironmentPublisherGrantJSON = errors.New("invalid environment publisher grant JSON")

// generated json tags supply the only field inventory. raw facts preserve exact
// spelling, duplicate detection and the one required nullable field; the generated
// model still owns decoding and wire types. no other null becomes a scalar zero.
func environmentPublisherGrantFields(model any) map[string]bool {
	t := reflect.TypeOf(model)
	fields := make(map[string]bool, t.NumField())
	for i := range t.NumField() {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			fields[name] = true
		}
	}
	return fields
}

func decodeEnvironmentPublisherGrantJSON(w http.ResponseWriter, r *http.Request) (body controlv1.AuthorizeEnvironmentPublisherServiceRequest, err error) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.URL.RawQuery != "" {
		return body, errEnvironmentPublisherGrantJSON
	}
	r.Body = http.MaxBytesReader(w, r.Body, environmentPublisherGrantBodyLimit)
	payload, err := httpjson.ReadAll(r.Body, environmentPublisherGrantBodyLimit)
	if err != nil {
		return body, err
	}
	if !utf8.Valid(payload) {
		return body, errEnvironmentPublisherGrantJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return body, errEnvironmentPublisherGrantJSON
	}
	allowed, seen := environmentPublisherGrantFields(body), map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return body, err
		}
		name, ok := token.(string)
		if !ok || !allowed[name] || seen[name] {
			return body, errEnvironmentPublisherGrantJSON
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return body, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && name != "expected_previous_grant_id" {
			return body, errEnvironmentPublisherGrantJSON
		}
	}
	if _, err := decoder.Token(); err != nil || !seen["expected_previous_grant_id"] {
		return body, errEnvironmentPublisherGrantJSON
	}
	if err := httpjson.Decode(json.NewDecoder(bytes.NewReader(payload)), &body); err != nil {
		return body, err
	}
	return body, nil
}

func validEnvironmentPublisherGrantQuery(r *http.Request, model any) bool {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return false
	}
	allowed := environmentPublisherGrantFields(model)
	for name, value := range values {
		if !allowed[name] || len(value) != 1 {
			return false
		}
	}
	return true
}
