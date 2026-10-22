// command storage-check validates resolved publisher parameter transitions offline.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tnldotdev/tnl/internal/publisher/deployment"
)

func main() {
	previous := flag.String("previous", "", "previous resolved AWS parameter JSON")
	next := flag.String("next", "", "next resolved AWS parameter JSON")
	flag.Parse()
	if err := check(*previous, *next); err != nil {
		fmt.Fprintln(os.Stderr, "publisher storage transition rejected:", err)
		os.Exit(1)
	}
}

func check(previous, next string) error {
	a, err := deployment.ReadParameters(previous)
	if err != nil {
		return err
	}
	b, err := deployment.ReadParameters(next)
	if err != nil {
		return err
	}
	return deployment.ValidateStorageTransition(a, b)
}
