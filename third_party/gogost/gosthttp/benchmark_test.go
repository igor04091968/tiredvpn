package gosthttp

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
)

func runBenchmarkServer(b *testing.B, server *http.Server, serve func() error) {
	b.Helper()
	serveErr := make(chan error, 1)
	go func() { serveErr <- serve() }()
	b.Cleanup(func() {
		_ = server.Close()
		select {
		case err := <-serveErr:
			if err != nil && err != http.ErrServerClosed {
				b.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			b.Error("HTTP benchmark server did not stop")
		}
	})
}

func benchmarkOrigin(b *testing.B, http1Only bool) (string, *gosttls.Config) {
	b.Helper()
	certificate, leaf := httpTestCertificate(b)
	listener := listenCounting(b)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
	if http1Only {
		runBenchmarkServer(b, server, func() error { return ServeHTTP1(server, listener, serverConfig) })
	} else {
		runBenchmarkServer(b, server, func() error { return Serve(server, listener, serverConfig) })
	}
	return "https://" + listener.Addr().String() + "/", clientConfigForLeaf(leaf)
}

func BenchmarkHTTP1KeepAlive(b *testing.B) {
	originURL, clientConfig := benchmarkOrigin(b, true)
	transport := NewHTTP1Transport(clientConfig)
	b.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	response, err := client.Get(originURL)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		response, err := client.Get(originURL)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			b.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTTP2Concurrent(b *testing.B) {
	originURL, clientConfig := benchmarkOrigin(b, false)
	transport := NewTransport(clientConfig)
	b.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	response, err := client.Get(originURL)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.ProtoMajor != 2 {
		b.Fatalf("negotiated %s, want HTTP/2", response.Proto)
	}

	var errorMu sync.Mutex
	var firstError error
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			errorMu.Lock()
			stopped := firstError != nil
			errorMu.Unlock()
			if stopped {
				return
			}
			response, err := client.Get(originURL)
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if err == nil {
					err = closeErr
				}
			}
			if err != nil {
				errorMu.Lock()
				if firstError == nil {
					firstError = err
				}
				errorMu.Unlock()
				return
			}
		}
	})
	if firstError != nil {
		b.Fatal(firstError)
	}
}

func BenchmarkCONNECT(b *testing.B) {
	for _, proxyScheme := range []string{"http", "https"} {
		b.Run(proxyScheme, func(b *testing.B) {
			originURL, clientConfig := benchmarkOrigin(b, true)
			certificate, proxyLeaf := httpTestCertificate(b)
			proxyListener := listenCounting(b)
			proxyServer := &http.Server{Handler: new(connectProxyHandler)}
			if proxyScheme == "https" {
				proxyConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
				runBenchmarkServer(b, proxyServer, func() error {
					return ServeHTTP1(proxyServer, proxyListener, proxyConfig)
				})
			} else {
				runBenchmarkServer(b, proxyServer, func() error { return proxyServer.Serve(proxyListener) })
			}
			proxyURL, err := url.Parse(proxyScheme + "://" + proxyListener.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			proxyTLSConfig := clientConfigForLeaf(proxyLeaf)

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				transport := NewHTTP1Transport(clientConfig)
				transport.Proxy = http.ProxyURL(proxyURL)
				if proxyScheme == "https" {
					transport.ProxyTLSClientConfig = proxyTLSConfig
				}
				client := &http.Client{Transport: transport}
				response, err := client.Get(originURL)
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					closeErr := response.Body.Close()
					if err == nil {
						err = closeErr
					}
				}
				transport.CloseIdleConnections()
				if err != nil {
					b.Fatal(fmt.Errorf("CONNECT request: %w", err))
				}
			}
		})
	}
}

func benchmarkPlainOrigin(b *testing.B) (string, net.Listener) {
	b.Helper()
	listener := listenCounting(b)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	})}
	runBenchmarkServer(b, server, func() error { return server.Serve(listener) })
	return "http://server.test:" + portOf(b, listener.Addr().String()) + "/", listener
}

func BenchmarkSOCKS5Handshake(b *testing.B) {
	originURL, originListener := benchmarkPlainOrigin(b)
	tests := []struct {
		name      string
		options   socks5TestOptions
		proxyUser *url.Userinfo
	}{
		{name: "no-auth"},
		{
			name: "username-password",
			options: socks5TestOptions{
				requireAuth: true,
				username:    "benchmark",
				password:    "password",
			},
			proxyUser: url.UserPassword("benchmark", "password"),
		},
	}
	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			options := test.options
			options.targetOverride = originListener.Addr().String()
			proxy := newSOCKS5TestServer(b, options)
			proxyURL := proxy.URL("socks5", test.proxyUser)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				transport := NewTransport(nil)
				transport.Proxy = http.ProxyURL(proxyURL)
				transport.DisableKeepAlives = true
				client := &http.Client{Transport: transport}
				response, err := client.Get(originURL)
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					closeErr := response.Body.Close()
					if err == nil {
						err = closeErr
					}
				}
				transport.CloseIdleConnections()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSOCKS5HTTP1KeepAlive(b *testing.B) {
	originURL, originListener := benchmarkPlainOrigin(b)
	proxy := newSOCKS5TestServer(b, socks5TestOptions{targetOverride: originListener.Addr().String()})
	transport := NewTransport(nil)
	transport.Proxy = http.ProxyURL(proxy.URL("socks5", nil))
	b.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	response, err := client.Get(originURL)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		response, err := client.Get(originURL)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			b.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSOCKS5HTTP2Concurrent(b *testing.B) {
	originURL, clientConfig := benchmarkOrigin(b, false)
	proxy := newSOCKS5TestServer(b, socks5TestOptions{})
	transport := NewTransport(clientConfig)
	transport.Proxy = http.ProxyURL(proxy.URL("socks5", nil))
	b.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	response, err := client.Get(originURL)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.ProtoMajor != 2 {
		b.Fatalf("negotiated %s, want HTTP/2", response.Proto)
	}

	var errorMu sync.Mutex
	var firstError error
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			errorMu.Lock()
			stopped := firstError != nil
			errorMu.Unlock()
			if stopped {
				return
			}
			response, err := client.Get(originURL)
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if err == nil {
					err = closeErr
				}
			}
			if err != nil {
				errorMu.Lock()
				if firstError == nil {
					firstError = err
				}
				errorMu.Unlock()
				return
			}
		}
	})
	if firstError != nil {
		b.Fatal(firstError)
	}
}
