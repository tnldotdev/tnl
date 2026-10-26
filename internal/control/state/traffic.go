package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

var ErrTrafficSelection = errors.New("controlstate: invalid traffic selection")

// publishRunTrafficDigest binds explicit selections to retries independently of
// current operator defaults. equivalent duration spellings share one digest.
func publishRunTrafficDigest(base [32]byte, selection *trafficlimits.Selection) ([32]byte, error) {
	s := trafficlimits.Selection{}
	if selection != nil {
		s = *selection
	}
	if err := s.Validate(); err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrTrafficSelection, err)
	}
	if s.RatePer != nil {
		period, _ := time.ParseDuration(*s.RatePer)
		value := period.String()
		s.RatePer = &value
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %v", ErrTrafficSelection, err)
	}
	h := sha256.New()
	_, _ = h.Write([]byte("tnl/publish-run/traffic/v1\x00"))
	_, _ = h.Write(base[:])
	_, _ = h.Write(payload)
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result, nil
}

func resolvePublishRunTraffic(request PublishRunRequest) ([]byte, error) {
	if request.GuestID != "" {
		// the trial's limits are server-owned and cannot be increased by a
		// publisher selection or wider operator defaults.
		return json.Marshal(trafficlimits.Guest())
	}
	defaults, ceiling := request.TrafficDefaults, request.TrafficCeiling
	if defaults == (trafficlimits.Limits{}) {
		defaults = trafficlimits.Default()
	}
	if ceiling == (trafficlimits.Limits{}) {
		ceiling = trafficlimits.Ceiling()
	}
	selection := trafficlimits.Selection{}
	if request.TrafficSelection != nil {
		selection = *request.TrafficSelection
	}
	resolved, err := selection.Resolve(defaults, ceiling)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrafficSelection, err)
	}
	return json.Marshal(resolved)
}

func decodePublishRunTraffic(payload []byte) (trafficlimits.Limits, error) {
	var limits trafficlimits.Limits
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&limits); err != nil {
		return limits, fmt.Errorf("controlstate: decode publish-run traffic limits: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !limits.Valid() || limits.RatePer == 0 {
		return limits, errors.New("controlstate: invalid stored publish-run traffic limits")
	}
	return limits, nil
}
