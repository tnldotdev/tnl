// Package feedbacktoolbar serves the versioned development-only browser script.
package feedbacktoolbar

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

//go:embed toolbar.js
var files embed.FS

func Script() ([]byte, string) {
	data, err := files.ReadFile("toolbar.js")
	if err != nil {
		panic("embedded feedback toolbar is missing")
	}
	digest := sha256.Sum256(data)
	return data, "/__tnl/feedback/toolbar." + hex.EncodeToString(digest[:6]) + ".js"
}
