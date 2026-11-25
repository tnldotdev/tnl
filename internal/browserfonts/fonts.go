// package browserfonts owns the bundled JetBrains Mono assets used by tnl browser UI.
package browserfonts

import _ "embed"

//go:embed jetbrains-mono-latin-wght-normal.woff2
var Latin []byte

//go:embed jetbrains-mono-symbols-wght-normal.woff2
var Symbols []byte
