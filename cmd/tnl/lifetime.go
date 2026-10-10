package main

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// parseWholeDayDuration handles the day suffix shared by share links and
// publish credentials. callers validate sub-day durations separately.
func parseWholeDayDuration(value string, maxDays int64) (time.Duration, bool, error) {
	days, found := strings.CutSuffix(value, "d")
	if !found {
		return 0, false, nil
	}
	count, err := strconv.ParseInt(days, 10, 64)
	if err != nil || count < 1 || count > maxDays {
		return 0, true, errors.New("whole-day lifetime is out of range")
	}
	return time.Duration(count) * 24 * time.Hour, true, nil
}
