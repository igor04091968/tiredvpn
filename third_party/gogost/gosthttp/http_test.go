package gosthttp

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func httpTestCertificate(t testing.TB) (gosttls.Certificate, *x509.Certificate) {
	t.Helper()
	private, err := gost3410.GenPrivateKey(gost3410.CurveIdtc26gost341012256paramSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "server.test"},
		DNSNames:              []string{"server.test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return gosttls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  &gost3410.PrivateKeyReverseDigestAndSignature{Prv: private},
		Leaf:        leaf,
	}, leaf
}

func TestHTTPClientAndServer(t *testing.T) {
	certificate, leaf := httpTestCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverConfig := gosttls.GOSTConfig(&gosttls.Config{
		Certificates: []gosttls.Certificate{certificate},
	})
	serverConfig.CipherSuitesTLS13 = []uint16{gosttls.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L}
	serverConfig.CurvePreferences = []gosttls.CurveID{gosttls.GOSTCurve256A}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.TLS != nil {
			http.Error(w, "standard TLS state unexpectedly populated", http.StatusInternalServerError)
			return
		}
		state, ok := ConnectionState(request)
		if !ok || state.CipherSuite != gosttls.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L {
			http.Error(w, "missing GOST TLS state", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, "gost-http-ok")
	})}
	serveErr := make(chan error, 1)
	go func() { serveErr <- Serve(server, listener, serverConfig) }()
	defer func() {
		_ = server.Close()
		select {
		case err := <-serveErr:
			if err != nil && err != http.ErrServerClosed {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("HTTP server did not stop")
		}
	}()

	clientConfig := gosttls.GOSTConfig(&gosttls.Config{RootCAs: roots, ServerName: "server.test"})
	clientConfig.CipherSuitesTLS13 = []uint16{gosttls.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L}
	clientConfig.CurvePreferences = []gosttls.CurveID{gosttls.GOSTCurve256A}
	client := NewClient(clientConfig)
	client.Timeout = 10 * time.Second
	transport := client.Transport.(*Transport)
	defer transport.CloseIdleConnections()

	response, err := client.Get("https://" + listener.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "gost-http-ok" {
		t.Fatalf("status=%s body=%q", response.Status, body)
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("negotiated %s, want HTTP/2", response.Proto)
	}
	if response.TLS != nil {
		t.Fatal("standard response TLS state unexpectedly populated")
	}
	responseState, ok := ResponseConnectionState(response)
	if !ok || responseState.CipherSuite != gosttls.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L {
		t.Fatalf("missing response GOST TLS state: ok=%v suite=%x", ok, responseState.CipherSuite)
	}
}

func TestServeRejectsMissingTLSConfig(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := new(http.Server)
	if err := Serve(server, listener, nil); err == nil {
		t.Fatal("Serve accepted a nil TLS config")
	}
	if err := Serve(server, listener, gosttls.GOSTConfig(nil)); err == nil {
		t.Fatal("Serve accepted a TLS config without a certificate source")
	}
}
