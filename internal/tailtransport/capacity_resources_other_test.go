//go:build !linux

package tailtransport

func currentRSS() int64 {
	return -1
}
