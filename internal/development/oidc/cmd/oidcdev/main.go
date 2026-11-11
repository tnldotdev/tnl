package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/development/oidc"
)

func main() {
	listen := flag.String("listen", ":8444", "development HTTP bind address")
	issuer := flag.String("issuer", "http://localhost:8444", "exact issuer")
	control := flag.String("control", "http://localhost:8445", "control origin")
	flag.Parse()
	p, err := oidc.New(oidc.Config{Issuer: *issuer, ClientID: "tnl-local", ClientSecret: "local-development-secret", Subject: "developer", RedirectURLs: []string{*control + "/v1/auth/device/callback", *control + "/v1/browser/callback"}})
	if err != nil {
		log.Fatal(err)
	}
	s := &http.Server{Addr: *listen, Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Fatal(s.ListenAndServe())
}
