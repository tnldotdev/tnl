package controlapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func publishRunTrafficSelection(w http.ResponseWriter, r *http.Request) (*trafficlimits.Selection, bool) {
	var raw json.RawMessage
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	if err := decodeJSON(w, r, &raw); err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid publish-run request")
		return nil, false
	}
	var body *controlv1.CreatePublishRunRequest
	if err := httpjson.Decode(json.NewDecoder(bytes.NewReader(raw)), &body); err != nil || body == nil || trafficHasNull(raw) {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid publish-run request")
		return nil, false
	}
	if body.Traffic == nil {
		return nil, true
	}
	s := body.Traffic
	selection := &trafficlimits.Selection{Connections: s.Connections, Rate: s.Rate, RatePer: s.RatePer,
		Burst: s.Burst, UploadBytes: s.UploadBytes, DownloadBytes: s.DownloadBytes,
		TotalConnections: s.TotalConnections, TotalUploadBytes: s.TotalUploadBytes, TotalDownloadBytes: s.TotalDownloadBytes}
	if err := selection.Validate(); err != nil {
		writeControlStateProblem(w, "select publish-run traffic limits", controlstate.ErrTrafficSelection)
		return nil, false
	}
	return selection, true
}

func trafficHasNull(raw json.RawMessage) bool {
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil {
		return true
	}
	value, present := body["traffic"]
	if !present {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(value, &fields) != nil || fields == nil {
		return true
	}
	for _, field := range fields {
		if bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
			return true
		}
	}
	return false
}

func trafficLimitsResponse(l trafficlimits.Limits) *controlv1.TrafficLimits {
	if !l.Valid() {
		return nil
	}
	r := &controlv1.TrafficLimits{Connections: l.Connections, Rate: l.Rate, RatePerNs: int64(l.Period()),
		Burst: l.Burst, UploadBytes: l.UploadBytes, DownloadBytes: l.DownloadBytes}
	if l.TotalConnections > 0 {
		r.TotalConnections = &l.TotalConnections
	}
	if l.TotalUploadBytes > 0 {
		r.TotalUploadBytes = &l.TotalUploadBytes
	}
	if l.TotalDownloadBytes > 0 {
		r.TotalDownloadBytes = &l.TotalDownloadBytes
	}
	return r
}
