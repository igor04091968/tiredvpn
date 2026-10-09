package gosthttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func standardProxyCertificate(t testing.TB) (stdtls.Certificate, *x509.Certificate) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &stdx509.Certificate{
		SerialNumber:          big.NewInt(700),
		Subject:               pkix.Name{CommonName: "proxy.test"},
		DNSNames:              []string{"proxy.test"},
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
	return stdtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  private,
		Leaf:        standardLeaf,
	}, gostLeaf
}

func TestHTTPSProxyWithStandardTLS(t *testing.T) {
	originCertificate, originLeaf := httpTestCertificate(t)
	originListener := listenCounting(t)
	originServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})}
	originConfig := gosttls.GOSTConfig(&gosttls.Config{
		Certificates: []gosttls.Certificate{originCertificate},
	})
	runServer(t, originServer, originListener, func() error {
		return Serve(originServer, originListener, originConfig)
	})

	proxyCertificate, proxyLeaf := standardProxyCertificate(t)
	proxyHandler := new(connectProxyHandler)
	proxyListener := listenCounting(t)
	proxyServer := &http.Server{Handler: proxyHandler}
	standardTLSListener := stdtls.NewListener(proxyListener, &stdtls.Config{
		Certificates: []stdtls.Certificate{proxyCertificate},
		MinVersion:   stdtls.VersionTLS13,
	})
	runServer(t, proxyServer, proxyListener, func() error {
		return proxyServer.Serve(standardTLSListener)
	})

	proxyURL := &url.URL{Scheme: "https", Host: proxyListener.Addr().String()}
	proxyRoots := x509.NewCertPool()
	proxyRoots.AddCert(proxyLeaf)
	transport := NewTransport(clientConfigForLeaf(originLeaf))
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.ProxyTLSClientConfig = &gosttls.Config{
		RootCAs:    proxyRoots,
		ServerName: "proxy.test",
		MinVersion: gosttls.VersionTLS13,
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("https://" + originListener.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 || string(body) != "ok" {
		t.Fatalf("protocol=%s body=%q", response.Proto, body)
	}
	if proxyHandler.connects.Load() != 1 || proxyListener.accepted.Load() != 1 {
		t.Fatalf("CONNECT=%d accepted=%d, want 1/1", proxyHandler.connects.Load(), proxyListener.accepted.Load())
	}
}

func TestStandardTLSOriginThroughSOCKS5(t *testing.T) {
	originCertificate, originLeaf := standardProxyCertificate(t)
	originListener := listenCounting(t)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	originServer := &http.Server{
		Protocols: protocols,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, "standard-tls-ok")
		}),
	}
	standardTLSListener := stdtls.NewListener(originListener, &stdtls.Config{
		Certificates: []stdtls.Certificate{originCertificate},
		MinVersion:   stdtls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	})
	runServer(t, originServer, originListener, func() error {
		return originServer.Serve(standardTLSListener)
	})

	proxy := newSOCKS5TestServer(t, socks5TestOptions{targetOverride: originListener.Addr().String()})
	roots := x509.NewCertPool()
	roots.AddCert(originLeaf)
	transport := NewHTTP1Transport(&gosttls.Config{
		RootCAs:    roots,
		ServerName: "proxy.test",
		MinVersion: gosttls.VersionTLS13,
	})
	transport.Proxy = http.ProxyURL(proxy.URL("socks5", nil))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("https://proxy.test:" + portOf(t, originListener.Addr().String()) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 1 || string(body) != "standard-tls-ok" {
		t.Fatalf("protocol=%s body=%q", response.Proto, body)
	}
	if proxy.connects.Load() != 1 || originListener.accepted.Load() != 1 {
		t.Fatalf("SOCKS connects=%d origin accepts=%d", proxy.connects.Load(), originListener.accepted.Load())
	}
}
