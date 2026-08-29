//go:build !linux

package processmetrics

func currentRSS() int64 {
	return -1
}
