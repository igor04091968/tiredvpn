package gosttls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func standardInteropCertificate(t *testing.T) (Certificate, stdtls.Certificate, *x509.Certificate, *stdx509.Certificate) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &stdx509.Certificate{
		SerialNumber:          big.NewInt(300),
		Subject:               pkix.Name{CommonName: "standard.test"},
		DNSNames:              []string{"standard.test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              stdx509.KeyUsageDigitalSignature | stdx509.KeyUsageCertSign,
		ExtKeyUsage:           []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := stdx509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	standardLeaf, err := stdx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	gostLeaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: gostLeaf},
		stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: standardLeaf},
		gostLeaf, standardLeaf
}

func TestStandardTLS13Interoperability(t *testing.T) {
	gostCertificate, standardCertificate, gostLeaf, standardLeaf := standardInteropCertificate(t)
	gostRoots := x509.NewCertPool()
	gostRoots.AddCert(gostLeaf)
	standardRoots := stdx509.NewCertPool()
	standardRoots.AddCert(standardLeaf)

	tests := []struct {
		name   string
		client func(net.Conn) interface{ Handshake() error }
		server func(net.Conn) interface{ Handshake() error }
	}{
		{
			name: "gosttls-client",
			client: func(conn net.Conn) interface{ Handshake() error } {
				return Client(conn, &Config{
					RootCAs:                gostRoots,
					ServerName:             "standard.test",
					MinVersion:             VersionTLS13,
					MaxVersion:             VersionTLS13,
					CipherSuitesTLS13:      []uint16{TLS_AES_128_GCM_SHA256},
					CurvePreferences:       []CurveID{X25519},
					SignatureSchemes:       []SignatureScheme{ECDSAWithP256AndSHA256},
					ClientSessionCache:     nil,
					SessionTicketsDisabled: true,
				})
			},
			server: func(conn net.Conn) interface{ Handshake() error } {
				return stdtls.Server(conn, &stdtls.Config{
					Certificates: []stdtls.Certificate{standardCertificate},
					MinVersion:   stdtls.VersionTLS13,
					MaxVersion:   stdtls.VersionTLS13,
				})
			},
		},
		{
			name: "gosttls-server",
			client: func(conn net.Conn) interface{ Handshake() error } {
				return stdtls.Client(conn, &stdtls.Config{
					RootCAs:    standardRoots,
					ServerName: "standard.test",
					MinVersion: stdtls.VersionTLS13,
					MaxVersion: stdtls.VersionTLS13,
				})
			},
			server: func(conn net.Conn) interface{ Handshake() error } {
				return Server(conn, &Config{
					Certificates:           []Certificate{gostCertificate},
					MinVersion:             VersionTLS13,
					MaxVersion:             VersionTLS13,
					CipherSuitesTLS13:      []uint16{TLS_AES_128_GCM_SHA256},
					CurvePreferences:       []CurveID{X25519},
					SignatureSchemes:       []SignatureScheme{ECDSAWithP256AndSHA256},
					SessionTicketsDisabled: true,
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			deadline := time.Now().Add(10 * time.Second)
			_ = clientSide.SetDeadline(deadline)
			_ = serverSide.SetDeadline(deadline)
			client := test.client(clientSide)
			server := test.server(serverSide)
			serverResult := make(chan error, 1)
			go func() { serverResult <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if err := <-serverResult; err != nil {
				t.Fatalf("server handshake: %v", err)
			}
		})
	}
}

func TestMixedDefaultsStandardTLS13Interoperability(t *testing.T) {
	gostCertificate, standardCertificate, gostLeaf, standardLeaf := standardInteropCertificate(t)
	gostRoots := x509.NewCertPool()
	gostRoots.AddCert(gostLeaf)
	standardRoots := stdx509.NewCertPool()
	standardRoots.AddCert(standardLeaf)

	tests := []struct {
		name   string
		client func(net.Conn) interface{ Handshake() error }
		server func(net.Conn) interface{ Handshake() error }
	}{
		{
			name: "gosttls-client-defaults",
			client: func(conn net.Conn) interface{ Handshake() error } {
				return Client(conn, &Config{
					RootCAs:                gostRoots,
					ServerName:             "standard.test",
					MinVersion:             VersionTLS13,
					MaxVersion:             VersionTLS13,
					SessionTicketsDisabled: true,
				})
			},
			server: func(conn net.Conn) interface{ Handshake() error } {
				return stdtls.Server(conn, &stdtls.Config{
					Certificates: []stdtls.Certificate{standardCertificate},
					MinVersion:   stdtls.VersionTLS13,
					MaxVersion:   stdtls.VersionTLS13,
				})
			},
		},
		{
			name: "gosttls-server-defaults",
			client: func(conn net.Conn) interface{ Handshake() error } {
				return stdtls.Client(conn, &stdtls.Config{
					RootCAs:    standardRoots,
					ServerName: "standard.test",
					MinVersion: stdtls.VersionTLS13,
					MaxVersion: stdtls.VersionTLS13,
				})
			},
			server: func(conn net.Conn) interface{ Handshake() error } {
				return Server(conn, &Config{
					Certificates:           []Certificate{gostCertificate},
					MinVersion:             VersionTLS13,
					MaxVersion:             VersionTLS13,
					SessionTicketsDisabled: true,
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			deadline := time.Now().Add(10 * time.Second)
			_ = clientSide.SetDeadline(deadline)
			_ = serverSide.SetDeadline(deadline)
			client := test.client(clientSide)
			server := test.server(serverSide)
			serverResult := make(chan error, 1)
			go func() { serverResult <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if err := <-serverResult; err != nil {
				t.Fatalf("server handshake: %v", err)
			}
		})
	}
}
