package public

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/tnldotdev/tnl/internal/httpjson"
)

const environmentRequestBodyLimit int64 = 4 << 20

var errEnvironmentJSONNull = errors.New("environment requests cannot contain null")

func decodeEnvironmentJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, environmentRequestBodyLimit)
	payload, err := httpjson.ReadAll(r.Body, environmentRequestBodyLimit)
	if err != nil {
		return err
	}
	// these request schemas have no nullable fields. inspect tokens before Go
	// pointers or scalar zero values erase explicit nulls; omission stays distinct.
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
			return errEnvironmentJSONNull
		}
	}
	return httpjson.Decode(json.NewDecoder(bytes.NewReader(payload)), target)
}
