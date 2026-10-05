// package browserfonts owns the bundled Fira Code assets used by tnl browser UI.
package browserfonts

import _ "embed"

//go:embed fira-code-latin-wght-normal.woff2
var Latin []byte

//go:embed fira-code-symbols2-wght-normal.woff2
var Symbols []byte
