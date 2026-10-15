package credentials

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// GuestVisitorToken is a URL-bound visitor capability derived from a guest
// credential hash. revealing it does not reveal the guest publisher credential.
func GuestVisitorToken(token AccessToken, guestID, publicURLID string) (string, error) {
	_, hash, err := ParseAccessToken(token)
	if err != nil || guestID == "" || publicURLID == "" {
		return "", errors.New("guest visitor credential is invalid")
	}
	return guestVisitorToken(hash[:], guestID, publicURLID), nil
}

func guestVisitorToken(key []byte, guestID, publicURLID string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("tnl/guest-visitor/v1\x00"))
	_, _ = mac.Write([]byte(publicURLID))
	return guestID + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func GuestVisitorTokenMatches(token, guestID, publicURLID string, storedHash []byte) bool {
	if len(storedHash) != 32 || !strings.HasPrefix(token, guestID+".") {
		return false
	}
	want := guestVisitorToken(storedHash, guestID, publicURLID)
	return hmac.Equal([]byte(token), []byte(want))
}
