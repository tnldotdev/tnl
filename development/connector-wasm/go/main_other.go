//go:build !js || !wasm

package main

func main() {
	panic("connector WASM spike requires GOOS=js GOARCH=wasm")
}
