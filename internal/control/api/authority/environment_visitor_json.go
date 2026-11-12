package authority

import (
	"net/http"

	"github.com/tnldotdev/tnl/internal/httpjson"
)

func decodeEnvironmentVisitorJSON(w http.ResponseWriter, r *http.Request, target any, required ...string) error {
	const limit int64 = 64 << 10
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	payload, err := httpjson.ReadAll(r.Body, limit)
	if err != nil {
		return err
	}
	return httpjson.DecodeNonNullObject(payload, target, required...)
}
