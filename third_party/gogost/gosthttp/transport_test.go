package gosthttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (listener *countingListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err == nil {
		listener.accepted.Add(1)
	}
	return conn, err
}

func listenCounting(t testing.TB) *countingListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return &countingListener{Listener: listener}
}

func runServer(t *testing.T, server *http.Server, listener net.Listener, serve func() error) {
	t.Helper()
	serveErr := make(chan error, 1)
	go func() { serveErr <- serve() }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serveErr:
			if err != nil && err != http.ErrServerClosed {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("HTTP server did not stop")
			_ = listener.Close()
		}
	})
}

func clientConfigForLeaf(leaf *x509.Certificate) *gosttls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return gosttls.GOSTConfig(&gosttls.Config{
		RootCAs:    roots,
		ServerName: "server.test",
	})
}

func TestAutomaticHTTP1(t *testing.T) {
	certificate, leaf := httpTestCertificate(t)
	listener := listenCounting(t)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	server := &http.Server{
		Protocols: protocols,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(w, request.Proto)
		}),
	}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
	runServer(t, server, listener, func() error { return Serve(server, listener, serverConfig) })

	transport := NewHTTP1Transport(clientConfigForLeaf(leaf))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("https://" + listener.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 1 || string(body) != "HTTP/1.1" {
		t.Fatalf("protocol=%s body=%q, want HTTP/1.1", response.Proto, body)
	}
	if listener.accepted.Load() != 1 {
		t.Fatalf("accepted %d connections, want 1", listener.accepted.Load())
	}
}

func TestHTTP1WithoutALPN(t *testing.T) {
	certificate, leaf := httpTestCertificate(t)
	listener := listenCounting(t)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	server := &http.Server{
		Protocols: protocols,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.WriteString(writer, request.Proto)
		}),
	}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{
		Certificates: []gosttls.Certificate{certificate},
		// Deliberately leave NextProtos empty to exercise the HTTP/1.1 ALPN
		// fallback in the client bridge.
	})
	secureListener := gosttls.NewListener(listener, serverConfig)
	runServer(t, server, listener, func() error { return server.Serve(secureListener) })

	transport := NewHTTP1Transport(clientConfigForLeaf(leaf))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("https://" + listener.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 1 || string(body) != "HTTP/1.1" {
		t.Fatalf("protocol=%s body=%q", response.Proto, body)
	}
}

func TestServeProtocolsApplyToDynamicTLSConfig(t *testing.T) {
	certificate, leaf := httpTestCertificate(t)
	listener := listenCounting(t)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, request.Proto)
	})}
	dynamic := gosttls.GOSTConfig(&gosttls.Config{
		Certificates: []gosttls.Certificate{certificate},
		NextProtos:   []string{"unsupported-by-http-bridge"},
	})
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{
		GetConfigForClient: func(*gosttls.ClientHelloInfo) (*gosttls.Config, error) {
			return dynamic, nil
		},
	})
	runServer(t, server, listener, func() error { return Serve(server, listener, serverConfig) })

	transport := NewTransport(clientConfigForLeaf(leaf))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("https://" + listener.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.ProtoMajor != 2 || string(body) != "HTTP/2.0" {
		t.Fatalf("protocol=%s body=%q, want HTTP/2.0", response.Proto, body)
	}
}

type connectProxyHandler struct {
	wantAuthorization string
	wantHeader        string
	connects          atomic.Int64
}

func (handler *connectProxyHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodConnect {
		http.Error(writer, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	if request.Header.Get("Proxy-Authorization") != handler.wantAuthorization ||
		request.Header.Get("X-GOST-Proxy") != handler.wantHeader {
		http.Error(writer, "proxy authentication failed", http.StatusProxyAuthRequired)
		return
	}
	handler.connects.Add(1)
	upstream, err := net.DialTimeout("tcp", request.Host, 5*time.Second)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(writer, "hijacking unavailable", http.StatusInternalServerError)
		return
	}
	downstream, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\nX-Proxy: accepted\r\n\r\n"); err != nil {
		_ = downstream.Close()
		_ = upstream.Close()
		return
	}
	if err := buffered.Flush(); err != nil {
		_ = downstream.Close()
		_ = upstream.Close()
		return
	}
	proxyTunnel(downstream, upstream, buffered.Reader)
}

func proxyTunnel(downstream, upstream net.Conn, buffered *bufio.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, buffered)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(downstream, upstream)
		done <- struct{}{}
	}()
	<-done
	_ = downstream.Close()
	_ = upstream.Close()
	<-done
}

func TestHTTP2ThroughConnectProxiesUsesOneTunnel(t *testing.T) {
	for _, proxyScheme := range []string{"http", "https"} {
		t.Run(proxyScheme, func(t *testing.T) {
			const parallelRequests = 8
			certificate, leaf := httpTestCertificate(t)
			originListener := listenCounting(t)
			var arrived atomic.Int64
			release := make(chan struct{})
			var releaseOnce sync.Once
			origin := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/parallel" {
					if arrived.Add(1) == parallelRequests {
						releaseOnce.Do(func() { close(release) })
					}
					select {
					case <-release:
					case <-request.Context().Done():
						return
					}
				}
				_, _ = io.WriteString(w, "ok")
			})}
			originConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
			runServer(t, origin, originListener, func() error { return Serve(origin, originListener, originConfig) })

			proxyHandler := &connectProxyHandler{
				wantAuthorization: "Basic dXNlcjpwYXNz",
				wantHeader:        "present",
			}
			proxyListener := listenCounting(t)
			proxyServer := &http.Server{Handler: proxyHandler}
			if proxyScheme == "https" {
				proxyConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
				runServer(t, proxyServer, proxyListener, func() error {
					return ServeHTTP1(proxyServer, proxyListener, proxyConfig)
				})
			} else {
				runServer(t, proxyServer, proxyListener, func() error {
					return proxyServer.Serve(proxyListener)
				})
			}

			proxyURL, err := url.Parse(proxyScheme + "://user:pass@" + proxyListener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			transport := NewTransport(clientConfigForLeaf(leaf))
			transport.Proxy = http.ProxyURL(proxyURL)
			transport.ProxyConnectHeader = http.Header{"X-GOST-Proxy": []string{"present"}}
			if proxyScheme == "https" {
				transport.ProxyTLSClientConfig = clientConfigForLeaf(leaf)
			}
			var proxyCallbacks atomic.Int64
			transport.OnProxyConnectResponse = func(
				_ context.Context,
				_ *url.URL,
				_ *http.Request,
				response *http.Response,
			) error {
				if response.Header.Get("X-Proxy") != "accepted" {
					return fmt.Errorf("missing proxy response header")
				}
				proxyCallbacks.Add(1)
				return nil
			}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
			originURL := "https://" + originListener.Addr().String()

			warm, err := client.Get(originURL + "/warm")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, warm.Body)
			_ = warm.Body.Close()
			if warm.ProtoMajor != 2 {
				t.Fatalf("negotiated %s through proxy, want HTTP/2", warm.Proto)
			}

			errorsByRequest := make(chan error, parallelRequests)
			for range parallelRequests {
				go func() {
					response, err := client.Get(originURL + "/parallel")
					if err == nil {
						_, err = io.Copy(io.Discard, response.Body)
						closeErr := response.Body.Close()
						if err == nil {
							err = closeErr
						}
					}
					errorsByRequest <- err
				}()
			}
			for range parallelRequests {
				if err := <-errorsByRequest; err != nil {
					t.Fatal(err)
				}
			}
			if originListener.accepted.Load() != 1 {
				t.Fatalf("origin accepted %d connections, want 1", originListener.accepted.Load())
			}
			if proxyHandler.connects.Load() != 1 || proxyCallbacks.Load() != 1 {
				t.Fatalf("CONNECT=%d callbacks=%d, want 1/1", proxyHandler.connects.Load(), proxyCallbacks.Load())
			}
			if proxyListener.accepted.Load() != 1 {
				t.Fatalf("proxy accepted %d connections, want 1", proxyListener.accepted.Load())
			}
		})
	}
}

func TestHTTP2StrictStreamLimitUsesOneConnection(t *testing.T) {
	const requests = 4
	certificate, leaf := httpTestCertificate(t)
	listener := listenCounting(t)
	started := make(chan struct{}, requests)
	release := make(chan struct{})
	var active atomic.Int64
	var maximum atomic.Int64
	server := &http.Server{
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 2},
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/limited" {
				current := active.Add(1)
				defer active.Add(-1)
				for {
					observed := maximum.Load()
					if current <= observed || maximum.CompareAndSwap(observed, current) {
						break
					}
				}
				started <- struct{}{}
				<-release
			}
			_, _ = io.WriteString(writer, "ok")
		}),
	}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
	runServer(t, server, listener, func() error { return Serve(server, listener, serverConfig) })

	transport := NewTransport(clientConfigForLeaf(leaf))
	transport.HTTP2 = &http.HTTP2Config{StrictMaxConcurrentRequests: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	originURL := "https://" + listener.Addr().String()
	warm, err := client.Get(originURL + "/warm")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, warm.Body)
	_ = warm.Body.Close()

	results := make(chan error, requests)
	for range requests {
		go func() {
			response, err := client.Get(originURL + "/limited")
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if err == nil {
					err = closeErr
				}
			}
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("two HTTP/2 streams did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("server stream limit was exceeded")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	for range requests {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if maximum.Load() > 2 {
		t.Fatalf("maximum concurrent streams=%d, want <=2", maximum.Load())
	}
	if listener.accepted.Load() != 1 {
		t.Fatalf("accepted %d connections, want 1", listener.accepted.Load())
	}
}

func TestServerRejectsALPNPrefaceMismatch(t *testing.T) {
	for _, test := range []struct {
		name       string
		nextProtos []string
		payload    string
	}{
		{
			name:       "h2-with-http1-request",
			nextProtos: []string{"h2"},
			payload:    "GET / HTTP/1.1\r\nHost: server.test\r\n\r\n",
		},
		{
			name:    "h2-preface-without-alpn",
			payload: string(http2ClientPreface),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, leaf := httpTestCertificate(t)
			listener := listenCounting(t)
			server := &http.Server{
				Handler:  http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
				ErrorLog: log.New(io.Discard, "", 0),
			}
			serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
			runServer(t, server, listener, func() error { return Serve(server, listener, serverConfig) })

			raw, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			clientConfig := clientConfigForLeaf(leaf)
			clientConfig.NextProtos = test.nextProtos
			secure := gosttls.Client(raw, clientConfig)
			_ = secure.SetDeadline(time.Now().Add(5 * time.Second))
			if err := secure.Handshake(); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if _, err := io.WriteString(secure, test.payload); err != nil {
				t.Fatalf("write mismatched protocol: %v", err)
			}
			var one [1]byte
			if _, err := secure.Read(one[:]); err == nil {
				t.Fatal("server accepted an HTTP protocol that did not match ALPN")
			}
		})
	}
}

func TestProxyConnectErrorAndCallback(t *testing.T) {
	proxyListener := listenCounting(t)
	var callbackCount atomic.Int64
	var sawAuthorization atomic.Bool
	proxyServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Proxy-Authorization") == "Basic dXNlcjpwYXNz" {
			sawAuthorization.Store(true)
		}
		writer.Header().Set("Proxy-Authenticate", `Basic realm="gost"`)
		http.Error(writer, "authentication required", http.StatusProxyAuthRequired)
	})}
	runServer(t, proxyServer, proxyListener, func() error { return proxyServer.Serve(proxyListener) })

	proxyURL, err := url.Parse("http://user:pass@" + proxyListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	transport := NewTransport(nil)
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.OnProxyConnectResponse = func(
		_ context.Context,
		_ *url.URL,
		_ *http.Request,
		response *http.Response,
	) error {
		if response.StatusCode != http.StatusProxyAuthRequired {
			return fmt.Errorf("callback status = %d", response.StatusCode)
		}
		callbackCount.Add(1)
		return nil
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	_, err = client.Get("https://server.test/")
	if err == nil {
		t.Fatal("CONNECT 407 unexpectedly succeeded")
	}
	var connectError *ProxyConnectError
	if !errors.As(err, &connectError) {
		t.Fatalf("error %T does not contain ProxyConnectError: %v", err, err)
	}
	if connectError.StatusCode != http.StatusProxyAuthRequired ||
		connectError.Header.Get("Proxy-Authenticate") == "" {
		t.Fatalf("unexpected CONNECT error: %+v", connectError)
	}
	if !sawAuthorization.Load() || callbackCount.Load() != 1 {
		t.Fatalf("authorization=%v callbacks=%d, want true/1", sawAuthorization.Load(), callbackCount.Load())
	}
	if strings.Contains(connectError.Proxy, "pass") {
		t.Fatalf("proxy error leaked credentials: %q", connectError.Proxy)
	}
}

func TestProxyConnectTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
	})

	proxyURL := &url.URL{Scheme: "http", Host: listener.Addr().String()}
	transport := NewTransport(nil)
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.ProxyConnectTimeout = 100 * time.Millisecond
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	started := time.Now()
	_, err = client.Get("https://server.test/")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CONNECT timeout error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("CONNECT timeout took %v", elapsed)
	}
}

func TestProxyTLSHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
	})

	proxyURL := &url.URL{Scheme: "https", Host: listener.Addr().String()}
	transport := NewTransport(nil)
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.ProxyTLSHandshakeTimeout = 100 * time.Millisecond
	transport.ProxyConnectTimeout = 5 * time.Second
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	started := time.Now()
	_, err = client.Get("https://server.test/")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("HTTPS-proxy handshake timeout error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("HTTPS-proxy handshake timeout took %v", elapsed)
	}
}

func TestMaxConnsWaiterCancellation(t *testing.T) {
	certificate, leaf := httpTestCertificate(t)
	listener := listenCounting(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "2")
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		if request.URL.Path == "/hold" {
			close(entered)
			<-release
		}
		_, _ = io.WriteString(writer, "ok")
	})}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
	runServer(t, server, listener, func() error { return ServeHTTP1(server, listener, serverConfig) })

	transport := NewHTTP1Transport(clientConfigForLeaf(leaf))
	transport.MaxConnsPerHost = 1
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	first, err := client.Get("https://" + listener.Addr().String() + "/hold")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Body.Close()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+listener.Addr().String()+"/waiting", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(request)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting request error = %v, want context deadline exceeded", err)
	}
	close(release)
	if _, err := io.Copy(io.Discard, first.Body); err != nil {
		t.Fatal(err)
	}
	if listener.accepted.Load() != 1 {
		t.Fatalf("accepted %d connections, want 1", listener.accepted.Load())
	}
}

func TestNewTransportProxyFromEnvironment(t *testing.T) {
	if os.Getenv("GOSTHTTP_PROXY_HELPER") == "1" {
		transport := NewTransport(nil)
		request, err := http.NewRequest(http.MethodGet, os.Getenv("GOSTHTTP_PROXY_REQUEST"), nil)
		if err != nil {
			t.Fatal(err)
		}
		proxy, err := transport.Proxy(request)
		if wantError := os.Getenv("GOSTHTTP_PROXY_WANT_ERROR"); wantError != "" {
			if err == nil || !strings.Contains(err.Error(), wantError) {
				t.Fatalf("proxy=%v error=%v, want error containing %q", proxy, err, wantError)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		want := os.Getenv("GOSTHTTP_PROXY_WANT")
		if want == "<nil>" {
			if proxy != nil {
				t.Fatalf("proxy=%v, want nil", proxy)
			}
			return
		}
		if proxy == nil || proxy.String() != want {
			t.Fatalf("proxy=%v, want %s", proxy, want)
		}
		return
	}

	tests := []struct {
		name      string
		request   string
		want      string
		wantError string
		env       []string
	}{
		{
			name:    "HTTPS_PROXY_precedes_ALL_PROXY",
			request: "https://external.test/",
			want:    "socks5://specific.test:1080",
			env: []string{
				"HTTPS_PROXY=socks5://specific.test:1080",
				"ALL_PROXY=socks5://fallback.test:1080",
			},
		},
		{
			name:    "HTTP_PROXY_precedes_ALL_PROXY",
			request: "http://external.test/",
			want:    "http://specific.test:8080",
			env: []string{
				"HTTP_PROXY=http://specific.test:8080",
				"ALL_PROXY=socks5://fallback.test:1080",
			},
		},
		{
			name:    "ALL_PROXY_HTTPS_fallback",
			request: "https://external.test/",
			want:    "socks5h://fallback.test:1080",
			env:     []string{"ALL_PROXY=socks5h://fallback.test:1080"},
		},
		{
			name:    "ALL_PROXY_HTTP_fallback",
			request: "http://external.test/",
			want:    "socks5://fallback.test:1080",
			env:     []string{"ALL_PROXY=socks5://fallback.test:1080"},
		},
		{
			name:    "NO_PROXY_applies_to_ALL_PROXY",
			request: "https://internal.test/",
			want:    "<nil>",
			env: []string{
				"ALL_PROXY=socks5://fallback.test:1080",
				"NO_PROXY=internal.test",
			},
		},
		{
			name:    "lowercase",
			request: "https://external.test/",
			want:    "socks5://lowercase.test:1080",
			env:     []string{"all_proxy=socks5://lowercase.test:1080"},
		},
		{
			name:      "CGI_rejects_HTTP_PROXY",
			request:   "http://external.test/",
			wantError: "refusing to use HTTP_PROXY",
			env: []string{
				"HTTP_PROXY=http://unsafe.test:8080",
				"REQUEST_METHOD=GET",
			},
		},
		{
			name:    "CGI_allows_ALL_PROXY",
			request: "http://external.test/",
			want:    "socks5://fallback.test:1080",
			env: []string{
				"ALL_PROXY=socks5://fallback.test:1080",
				"REQUEST_METHOD=GET",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestNewTransportProxyFromEnvironment$")
			for _, variable := range os.Environ() {
				name, _, _ := strings.Cut(variable, "=")
				upperName := strings.ToUpper(name)
				if upperName == "HTTP_PROXY" || upperName == "HTTPS_PROXY" || upperName == "NO_PROXY" ||
					upperName == "ALL_PROXY" || upperName == "REQUEST_METHOD" ||
					strings.HasPrefix(upperName, "GOSTHTTP_PROXY_") {
					continue
				}
				command.Env = append(command.Env, variable)
			}
			command.Env = append(command.Env,
				"GOSTHTTP_PROXY_HELPER=1",
				"GOSTHTTP_PROXY_REQUEST="+test.request,
				"GOSTHTTP_PROXY_WANT="+test.want,
				"GOSTHTTP_PROXY_WANT_ERROR="+test.wantError,
			)
			command.Env = append(command.Env, test.env...)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("proxy helper: %v\n%s", err, output)
			}
		})
	}
}

func TestCanonicalIPv6Addresses(t *testing.T) {
	target, name, scheme, err := canonicalRequestAddress(&url.URL{Scheme: "https", Host: "[2001:db8::1]"})
	if err != nil {
		t.Fatal(err)
	}
	if target != "[2001:db8::1]:443" || name != "2001:db8::1" || scheme != "https" {
		t.Fatalf("target=%q name=%q scheme=%q", target, name, scheme)
	}
	proxy, err := canonicalProxyAddress(&url.URL{Scheme: "https", Host: "[2001:db8::2]"})
	if err != nil {
		t.Fatal(err)
	}
	if proxy != "[2001:db8::2]:443" {
		t.Fatalf("proxy=%q", proxy)
	}
	idnaTarget, idnaName, _, err := canonicalRequestAddress(&url.URL{Scheme: "https", Host: "пример.рф"})
	if err != nil {
		t.Fatal(err)
	}
	if idnaTarget != "xn--e1afmkfd.xn--p1ai:443" || idnaName != "xn--e1afmkfd.xn--p1ai" {
		t.Fatalf("IDNA target=%q name=%q", idnaTarget, idnaName)
	}
}

func TestSOCKSProxySchemesAndDefaultPort(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h", "SoCkS5"} {
		proxyURL, err := normalizeProxyURL(&url.URL{Scheme: scheme, Host: "proxy.test"})
		if err != nil {
			t.Fatal(err)
		}
		if proxyURL.Scheme != strings.ToLower(scheme) {
			t.Fatalf("normalized scheme=%q", proxyURL.Scheme)
		}
		address, err := canonicalProxyAddress(proxyURL)
		if err != nil {
			t.Fatal(err)
		}
		if address != "proxy.test:1080" {
			t.Fatalf("proxy address=%q", address)
		}
	}
}

func TestDynamicProxyConnectHeadersAndPoolKey(t *testing.T) {
	proxyURL, err := url.Parse("http://user:secret@proxy.test:8080")
	if err != nil {
		t.Fatal(err)
	}
	transport := NewTransport(nil)
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.ProxyConnectHeader = http.Header{"X-Static": []string{"ignored"}}
	transport.GetProxyConnectHeader = func(
		_ context.Context,
		_ *url.URL,
		target string,
	) (http.Header, error) {
		return http.Header{"X-Dynamic": []string{target}}, nil
	}
	request, err := http.NewRequest(http.MethodGet, "https://origin.test:8443/", nil)
	if err != nil {
		t.Fatal(err)
	}
	route, err := transport.routeForRequest(request, proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	if route.connectHeader.Get("X-Static") != "" ||
		route.connectHeader.Get("X-Dynamic") != "origin.test:8443" ||
		route.connectHeader.Get("Proxy-Authorization") == "" {
		t.Fatalf("unexpected CONNECT headers: %v", route.connectHeader)
	}
	if route.key.proxyAuth != headerFingerprint(route.connectHeader) {
		t.Fatal("pool key does not include the CONNECT header fingerprint")
	}
	if strings.Contains(fmt.Sprint(route.key), "secret") {
		t.Fatal("pool key string leaked the proxy password")
	}
	lowercase := headerFingerprint(http.Header{"x-connect-token": []string{"one"}})
	canonical := headerFingerprint(http.Header{"X-Connect-Token": []string{"one"}})
	different := headerFingerprint(http.Header{"x-connect-token": []string{"two"}})
	if lowercase != canonical || lowercase == different {
		t.Fatal("CONNECT header fingerprint does not match canonical wire semantics")
	}
	ordered := headerFingerprint(http.Header{"X-Ordered": []string{"one", "two"}})
	reversed := headerFingerprint(http.Header{"X-Ordered": []string{"two", "one"}})
	if ordered == reversed {
		t.Fatal("CONNECT header fingerprint ignored repeated-value order")
	}
}

func TestNewTransportSessionCachePolicy(t *testing.T) {
	defaults := NewTransport(nil)
	if defaults.TLSClientConfig.ClientSessionCache == nil ||
		defaults.ProxyTLSClientConfig.ClientSessionCache == nil {
		t.Fatal("NewTransport(nil) did not configure both session caches")
	}
	if defaults.TLSClientConfig.ClientSessionCache == defaults.ProxyTLSClientConfig.ClientSessionCache {
		t.Fatal("origin and HTTPS-proxy session caches are not independent")
	}

	userCache := gosttls.NewLRUClientSessionCache(7)
	userConfig := &gosttls.Config{ClientSessionCache: userCache}
	custom := NewTransport(userConfig)
	if custom.TLSClientConfig == userConfig {
		t.Fatal("NewTransport did not clone the caller's TLS config")
	}
	if custom.TLSClientConfig.ClientSessionCache != userCache {
		t.Fatal("NewTransport changed the caller's session cache policy")
	}
}

func TestHTTPTraceDoesNotFabricateStandardTLSState(t *testing.T) {
	certificate, leaf := httpTestCertificate(t)
	listener := listenCounting(t)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
	runServer(t, server, listener, func() error { return ServeHTTP1(server, listener, serverConfig) })

	transport := NewHTTP1Transport(clientConfigForLeaf(leaf))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	traceState := make(chan tls.ConnectionState, 1)
	var starts atomic.Int64
	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() { starts.Add(1) },
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil {
				traceState <- state
			}
		},
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+listener.Addr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	state := <-traceState
	if starts.Load() != 1 || state.Version != 0 || state.HandshakeComplete ||
		state.CipherSuite != 0 || state.NegotiatedProtocol != "" || len(state.PeerCertificates) != 0 {
		t.Fatalf("fabricated crypto/tls trace state: %+v", state)
	}
	if gostState, ok := ResponseConnectionState(response); !ok || !gostState.HandshakeComplete {
		t.Fatal("complete GOST connection state is unavailable on the response")
	}
}

func TestHTTP1RetriesOnlyReplayableRequestOnStaleConnection(t *testing.T) {
	certificate, leaf := httpTestCertificate(t)
	listener := listenCounting(t)
	var dropReplayable atomic.Bool
	var dropNonReplayable atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		shouldDrop := request.URL.Path == "/retry" && dropReplayable.CompareAndSwap(false, true)
		shouldDrop = shouldDrop || request.URL.Path == "/no-retry" && dropNonReplayable.CompareAndSwap(false, true)
		if shouldDrop {
			conn, _, err := writer.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack stale connection: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		_, _ = io.WriteString(writer, "ok")
	})}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
	runServer(t, server, listener, func() error { return ServeHTTP1(server, listener, serverConfig) })

	transport := NewHTTP1Transport(clientConfigForLeaf(leaf))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	originURL := "https://" + listener.Addr().String()

	warm, err := client.Get(originURL + "/warm")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, warm.Body)
	_ = warm.Body.Close()

	response, err := client.Get(originURL + "/retry")
	if err != nil {
		t.Fatalf("replayable request was not retried: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "ok" {
		t.Fatalf("retried response body=%q err=%v", body, err)
	}
	if listener.accepted.Load() != 2 {
		t.Fatalf("accepted %d connections after stale retry, want 2", listener.accepted.Load())
	}

	request, err := http.NewRequest(http.MethodPost, originURL+"/no-retry",
		io.NopCloser(strings.NewReader("not replayable")))
	if err != nil {
		t.Fatal(err)
	}
	request.GetBody = nil
	if _, err := client.Do(request); err == nil {
		t.Fatal("non-replayable request was retried after a stale connection failure")
	}
	if listener.accepted.Load() != 2 {
		t.Fatalf("non-replayable request opened a retry connection: accepted=%d", listener.accepted.Load())
	}
}

func TestHTTP2StreamCancellationKeepsConnectionReusable(t *testing.T) {
	certificate, leaf := httpTestCertificate(t)
	listener := listenCounting(t)
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/cancel" {
			started <- struct{}{}
			<-request.Context().Done()
			canceled <- struct{}{}
			return
		}
		_, _ = io.WriteString(writer, "ok")
	})}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
	runServer(t, server, listener, func() error { return Serve(server, listener, serverConfig) })

	transport := NewTransport(clientConfigForLeaf(leaf))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	originURL := "https://" + listener.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, originURL+"/cancel", nil)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		response, requestErr := client.Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		result <- requestErr
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP/2 request did not reach the server")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled HTTP/2 request error=%v, want context.Canceled", err)
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP/2 stream cancellation did not reach the server")
	}

	response, err := client.Get(originURL + "/after-cancel")
	if err != nil {
		t.Fatalf("connection was not reusable after stream cancellation: %v", err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.ProtoMajor != 2 || listener.accepted.Load() != 1 {
		t.Fatalf("protocol=%s accepted=%d, want HTTP/2 on one connection", response.Proto, listener.accepted.Load())
	}
}

func TestHTTP2GOAWAYOpensReplacementConnection(t *testing.T) {
	certificate, leaf := httpTestCertificate(t)
	firstListener := listenCounting(t)
	address := firstListener.Addr().String()
	firstServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "first")
	})}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
	firstServeErr := make(chan error, 1)
	go func() { firstServeErr <- Serve(firstServer, firstListener, serverConfig) }()
	t.Cleanup(func() { _ = firstServer.Close() })

	transport := NewTransport(clientConfigForLeaf(leaf))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	originURL := "https://" + address
	warm, err := client.Get(originURL + "/warm")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, warm.Body)
	_ = warm.Body.Close()
	if warm.ProtoMajor != 2 {
		t.Fatalf("warm request negotiated %s, want HTTP/2", warm.Proto)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = firstServer.Shutdown(shutdownCtx)
	cancel()
	if err != nil {
		t.Fatalf("graceful HTTP/2 shutdown: %v", err)
	}
	select {
	case err := <-firstServeErr:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("first Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first HTTP/2 server did not stop")
	}

	baseSecondListener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listen on the same endpoint after GOAWAY: %v", err)
	}
	secondListener := &countingListener{Listener: baseSecondListener}
	secondServer := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "second")
	})}
	secondServeErr := make(chan error, 1)
	go func() { secondServeErr <- Serve(secondServer, secondListener, serverConfig) }()
	t.Cleanup(func() {
		_ = secondServer.Close()
		select {
		case serveErr := <-secondServeErr:
			if serveErr != nil && serveErr != http.ErrServerClosed {
				t.Errorf("second Serve: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("second HTTP/2 server did not stop")
			_ = secondListener.Close()
		}
	})

	response, err := client.Get(originURL + "/after-goaway")
	if err != nil {
		t.Fatalf("request after GOAWAY: %v", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "second" {
		t.Fatalf("replacement response body=%q err=%v", body, err)
	}
	if response.ProtoMajor != 2 || firstListener.accepted.Load() != 1 || secondListener.accepted.Load() != 1 {
		t.Fatalf("protocol=%s accepted first/second=%d/%d, want HTTP/2 and 1/1",
			response.Proto, firstListener.accepted.Load(), secondListener.accepted.Load())
	}
}
