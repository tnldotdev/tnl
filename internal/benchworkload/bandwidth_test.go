package benchworkload

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBandwidthModesAndStreamWireDirections(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want []bandwidthDirection
	}{
		{BandwidthDownstream, []bandwidthDirection{bandwidthDownstream}},
		{BandwidthUpstream, []bandwidthDirection{bandwidthUpstream}},
		{BandwidthBidirectional, []bandwidthDirection{bandwidthDownstream, bandwidthUpstream}},
	} {
		mode := bandwidthMode(tc.mode)
		if !mode.valid() {
			t.Fatalf("invalid request mode %q", mode)
		}
		directions := mode.directions()
		if len(directions) != len(tc.want) {
			t.Fatal("incorrect stream count for mode")
		}
		for index, direction := range directions {
			parsed, ok := parseBandwidthDirection(string(direction))
			if !ok || parsed != tc.want[index] {
				t.Fatal("request mode became an invalid stream direction")
			}
		}
	}
	for _, value := range []string{"", BandwidthBidirectional, "UPSTREAM", "invalid"} {
		if _, ok := parseBandwidthDirection(value); ok {
			t.Fatalf("accepted wire direction %q", value)
		}
		request := httptest.NewRequest(http.MethodGet, "https://bench.example/bandwidth", nil)
		request.Header.Set(bandwidthDirectionHeader, value)
		response := httptest.NewRecorder()
		serveBandwidth(response, request)
		if response.Code != http.StatusBadRequest || response.Body.String() != "invalid bandwidth direction\n" {
			t.Fatal("invalid wire direction did not retain its HTTP rejection")
		}
	}
	request := httptest.NewRequest(http.MethodPost, "https://bench.example/bandwidth", bytes.NewReader(Payload(4)))
	request.Header.Set(bandwidthDirectionHeader, BandwidthUpstream)
	request.Header.Set(bandwidthRateHeader, "4")
	request.Header.Set(bandwidthDurationHeader, "1000000000")
	response := httptest.NewRecorder()
	serveBandwidth(response, request)
	if response.Code != http.StatusOK || response.Header().Get(bandwidthBytesHeader) != "4" {
		t.Fatal("upstream wire acknowledgement changed")
	}
	data, err := json.Marshal(BandwidthStreamResult{Direction: string(bandwidthUpstream), ExpectedBytes: 4, Bytes: 4})
	const want = `{"index":0,"url":"","direction":"upstream","expected_bytes":4,"bytes":4}`
	if err != nil || string(data) != want {
		t.Fatalf("stream JSON = %s, %v", data, err)
	}
}
