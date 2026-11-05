package main

import "testing"

func TestRuntimeRecordingValidation(t *testing.T) {
	for _, tc := range []struct {
		workload, mode, timing, cpus, gomaxprocs string
		valid                                    bool
	}{
		{"postgres", "live", "false", "1", "2", true},
		{"postgres", "buffered", "true", "2", "2", true},
		{"postgres", "buffered", "1", "0.5", "2", true},
		{"public-url", "", "", "", "", true},
		{"postgres", "local", "false", "1", "2", false},
		{"postgres", "live", "invalid", "1", "2", false},
		{"connect", "buffered", "false", "1", "2", false},
		{"connect", "live", "true", "1", "2", false},
		{"postgres", "live", "false", "NaN", "2", false},
		{"postgres", "live", "false", "+Inf", "2", false},
		{"postgres", "live", "false", "0", "2", false},
		{"postgres", "live", "false", "1", "0", false},
		{"postgres", "live", "false", "1", "1.5", false},
	} {
		if err := validateRuntimeRecording(tc.workload, tc.mode, tc.timing, tc.cpus, tc.gomaxprocs); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}
