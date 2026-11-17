package applicationlimits

import (
	"testing"
	"time"
)

func TestRequestBodyIdleTimeout(t *testing.T) {
	if timeout, err := RequestBodyIdleTimeout(nil); err != nil || timeout != 30*time.Second {
		t.Fatal("omission did not use the approved default", timeout, err)
	}
	for _, value := range []string{"0", "0s", "-1s", "invalid", "2562048h"} {
		if _, err := RequestBodyIdleTimeout(&value); err == nil {
			t.Fatal("invalid timeout was accepted", value)
		}
	}
	if timeout, err := RequestBodyIdleTimeout(new("45s")); err != nil || timeout != 45*time.Second {
		t.Fatal("configured timeout was lost", timeout, err)
	}
}
