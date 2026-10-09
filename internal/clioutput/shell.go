package clioutput

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:generate go run ../../scripts/generate-installer.go -root ../..

//go:embed shell.awk
var shellSource string

// ShellFunction returns a POSIX shell backend for frames with one Fields block.
// arguments are command, state, footer, then label/value pairs; values are passed
// through the environment so awk does not interpret backslashes as escapes.
func ShellFunction() string {
	return fmt.Sprintf(`tnl_frame() (
  export TNL_FRAME_COMMAND="$1" TNL_FRAME_STATE="$2" TNL_FRAME_FOOTER="$3"
  shift 3
  count=0
  while [ "$#" -ge 2 ]; do
    count=$((count + 1))
    export "TNL_FRAME_LABEL_$count=$1" "TNL_FRAME_VALUE_$count=$2"
    shift 2
  done
  [ "$#" -eq 0 ] || exit 2
  export TNL_FRAME_COUNT="$count"
  LC_ALL=C awk -v default_width=%d -v max_width=%d -v padding=%d \
    -v top_format=%s -v footer_format=%s %s </dev/null
)
`, defaultWidth, maxWidth, framePadding, shellQuote(topFormat), shellQuote(footerFormat), shellQuote(shellSource))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
