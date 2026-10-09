package gosttls_test

import (
	"io"
	"log"
	"os"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func ExampleDial() {
	caPEM, err := os.ReadFile("gost-ca.pem")
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		log.Fatal("gost-ca.pem contains no certificates")
	}

	config := gosttls.GOSTConfig(&gosttls.Config{
		RootCAs:    roots,
		ServerName: "server.example",
	})
	conn, err := gosttls.Dial("tcp", "server.example:8443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello\n")); err != nil {
		log.Fatal(err)
	}
}

func ExampleListen() {
	certificate, err := gosttls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		log.Fatal(err)
	}
	config := gosttls.GOSTConfig(&gosttls.Config{
		Certificates: []gosttls.Certificate{certificate},
	})

	listener, err := gosttls.Listen("tcp", ":8443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}
