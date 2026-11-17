package tnl

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// ordinary sdk fixtures must not send product telemetry to the real receiver.
	// telemetry proofs remove this override and capture the actual sender locally.
	if err := os.Setenv("TNL_NO_TELEMETRY", "1"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
