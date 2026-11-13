package state

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestNewPublisherAllocationUsesPrefixFreeLabelAndChecksFullHostname(t *testing.T) {
	host, err := newEphemeralHostname("approved.example.test")
	if err != nil || !regexp.MustCompile(`^[a-z2-7]{26}\.approved\.example\.test$`).MatchString(host) {
		t.Fatal("unexpected new allocation hostname", host, err)
	}
	for _, namespace := range []string{"Approved.example.test", "", strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 35)} {
		if _, err := newEphemeralHostname(namespace); !errors.Is(err, ErrPublicURLInvalid) {
			t.Fatal("accepted invalid or overlong allocation hostname", err)
		}
	}
}
