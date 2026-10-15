// this disposable app gives each Compose container a distinct HTTP response.
package main

import (
	"io"
	"net/http"
	"os"
)

func main() {
	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	if err := http.ListenAndServe(":3000", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, name)
	})); err != nil {
		panic(err)
	}
}
