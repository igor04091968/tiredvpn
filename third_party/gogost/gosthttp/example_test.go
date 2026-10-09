package gosthttp_test

import (
	"log"
	"net"
	"net/http"
	"os"

	"gitverse.ru/uzer_007/gogost/v3/gosthttp"
	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func ExampleNewClient() {
	caPEM, err := os.ReadFile("gost-ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("gost-ca.pem contains no certificates")
	}

	client := gosthttp.NewClient(gosttls.GOSTConfig(&gosttls.Config{
		RootCAs:    roots,
		ServerName: "server.example",
	}))
	response, err := client.Get("https://server.example:8443/")
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
}

func ExampleServe() {
	certificate, err := gosttls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}
	config := gosttls.GOSTConfig(&gosttls.Config{
		Certificates: []gosttls.Certificate{certificate},
	})

	listener, err := net.Listen("tcp", ":8443")
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state, ok := gosthttp.ConnectionState(r); ok {
			w.Header().Set("X-TLS-Version", gosttls.VersionName(state.Version))
		}
		_, _ = w.Write([]byte("GOST TLS\n"))
	})}
	log.Fatal(gosthttp.Serve(server, listener, config))
}
