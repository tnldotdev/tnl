package state

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestNewPublisherAllocationUsesServiceKindAndChecksFullHostname(t *testing.T) {
	host, err := newEphemeralHostname("approved.example.test")
	if err != nil || !regexp.MustCompile(`^s-[a-z2-7]{26}\.approved\.example\.test$`).MatchString(host) {
		t.Fatal("unexpected new allocation hostname", host, err)
	}
	for _, namespace := range []string{"Approved.example.test", "", strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 35)} {
		if _, err := newEphemeralHostname(namespace); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("accepted invalid or overlong allocation hostname", err)
		}
	}
}
