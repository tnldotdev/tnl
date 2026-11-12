package public

import (
	"net/http"

	"github.com/tnldotdev/tnl/internal/httpjson"
)

const environmentRequestBodyLimit int64 = 4 << 20

func decodeEnvironmentJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, environmentRequestBodyLimit)
	payload, err := httpjson.ReadAll(r.Body, environmentRequestBodyLimit)
	if err != nil {
		return err
	}
	return httpjson.DecodeNonNullObject(payload, target)
}
