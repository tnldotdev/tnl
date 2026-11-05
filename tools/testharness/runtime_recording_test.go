package main

import "testing"

func TestRuntimeRecordingValidation(t *testing.T) {
	for _, tc := range []struct {
		workload, mode, timing, late, cpus, gomaxprocs string
		valid                                          bool
	}{
		{"postgres", "live", "false", "off", "1", "2", true},
		{"postgres", "buffered", "true", "sample", "2", "2", true},
		{"postgres", "buffered", "1", "trace", "0.5", "2", true},
		{"public-url", "", "", "", "", "", true},
		{"postgres", "local", "false", "off", "1", "2", false},
		{"postgres", "live", "invalid", "off", "1", "2", false},
		{"connect", "buffered", "false", "off", "1", "2", false},
		{"connect", "live", "true", "off", "1", "2", false},
		{"postgres", "live", "false", "off", "NaN", "2", false},
		{"postgres", "live", "false", "off", "+Inf", "2", false},
		{"postgres", "live", "false", "off", "0", "2", false},
		{"postgres", "live", "false", "off", "1", "0", false},
		{"postgres", "live", "false", "off", "1", "1.5", false},
		{"postgres", "live", "false", "sample", "1", "2", false},
		{"postgres", "live", "", "trace", "1", "2", false},
		{"postgres", "live", "true", "invalid", "1", "2", false},
		{"connect", "live", "false", "trace", "1", "2", false},
	} {
		if err := validateRuntimeRecording(tc.workload, tc.mode, tc.timing, tc.late, tc.cpus, tc.gomaxprocs); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}
