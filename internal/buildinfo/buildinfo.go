package buildinfo

import "fmt"

var (
	Version = "devel"
	Commit  = ""
)

func Line(command string) string {
	if Commit == "" {
		return fmt.Sprintf("%s %s", command, Version)
	}
	return fmt.Sprintf("%s %s (%s)", command, Version, Commit)
}
