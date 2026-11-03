package trafficlimits

import (
	"testing"
	"time"
)

func TestValidateDefaults(t *testing.T) {
	defaults, ceiling := Default(), Ceiling()
	if err := ValidateDefaults(defaults, ceiling); err != nil {
		t.Fatal(err)
	}
	defaults.RatePer = time.Millisecond
	if err := ValidateDefaults(defaults, ceiling); err == nil {
		t.Fatal("equivalent rate exceeded ceiling")
	}
}
