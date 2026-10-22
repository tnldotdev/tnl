package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/development/oidc"
)

func main() {
	listen := flag.String("listen", ":8444", "development HTTPS bind address")
	issuer := flag.String("issuer", "https://identity.127.0.0.1.nip.io:8444", "exact issuer")
	control := flag.String("control", "https://control.127.0.0.1.nip.io:8445", "control origin")
	cert := flag.String("cert", "/etc/tnl/local.crt", "TLS certificate")
	key := flag.String("key", "/etc/tnl/local.key", "TLS key")
	flag.Parse()
	p, err := oidc.New(oidc.Config{Issuer: *issuer, ClientID: "tnl-local", ClientSecret: "local-development-secret", Subject: "developer", RedirectURLs: []string{*control + "/v1/auth/device/callback", *control + "/v1/browser/callback"}})
	if err != nil {
		log.Fatal(err)
	}
	s := &http.Server{Addr: *listen, Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Fatal(s.ListenAndServeTLS(*cert, *key))
}
