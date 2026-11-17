//go:build js && wasm && !tnlpublisher

package main

import "syscall/js"

func registerSelectedConnector(api js.Value) { registerConnector(api) }
