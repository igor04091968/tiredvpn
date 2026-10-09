package gosthttp

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
)

type socks5TestOptions struct {
	targetOverride       string
	requireAuth          bool
	preferNoAuth         bool
	acceptAnyCredentials bool
	username             string
	password             string
	reply                byte
}

type socks5Observation struct {
	addressType byte
	host        string
	port        uint16
	username    string
	password    string
}

type socks5TestServer struct {
	t       testing.TB
	options socks5TestOptions

	listener net.Listener
	accepted atomic.Int64
	connects atomic.Int64

	observations chan socks5Observation
	done         chan struct{}
	closeOnce    sync.Once
	wg           sync.WaitGroup
	mu           sync.Mutex
	connections  map[net.Conn]struct{}
}

func newSOCKS5TestServer(t testing.TB, options socks5TestOptions) *socks5TestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &socks5TestServer{
		t:            t,
		options:      options,
		listener:     listener,
		observations: make(chan socks5Observation, 64),
		done:         make(chan struct{}),
		connections:  make(map[net.Conn]struct{}),
	}
	server.wg.Add(1)
	go server.serve()
	t.Cleanup(server.Close)
	return server
}

func (server *socks5TestServer) URL(scheme string, user *url.Userinfo) *url.URL {
	return &url.URL{Scheme: scheme, Host: server.listener.Addr().String(), User: user}
}

func (server *socks5TestServer) Close() {
	server.closeOnce.Do(func() {
		close(server.done)
		_ = server.listener.Close()
		server.mu.Lock()
		for conn := range server.connections {
			_ = conn.Close()
		}
		server.mu.Unlock()
		server.wg.Wait()
	})
}

func (server *socks5TestServer) serve() {
	defer server.wg.Done()
	for {
		conn, err := server.listener.Accept()
		if err != nil {
			select {
			case <-server.done:
				return
			default:
				server.t.Errorf("SOCKS5 Accept: %v", err)
				return
			}
		}
		server.accepted.Add(1)
		server.mu.Lock()
		server.connections[conn] = struct{}{}
		server.mu.Unlock()
		server.wg.Add(1)
		go func() {
			defer server.wg.Done()
			defer func() {
				_ = conn.Close()
				server.mu.Lock()
				delete(server.connections, conn)
				server.mu.Unlock()
			}()
			if err := server.handle(conn); err != nil {
				select {
				case <-server.done:
				default:
					server.t.Errorf("SOCKS5 server: %v", err)
				}
			}
		}()
	}
}

func (server *socks5TestServer) handle(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:2]); err != nil {
		return err
	}
	if header[0] != socks5Version || header[1] == 0 {
		return fmt.Errorf("invalid greeting %x", header[:2])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	method := byte(socks5AuthNone)
	if server.options.requireAuth {
		method = socks5AuthUsernamePassword
	} else if server.options.preferNoAuth {
		method = socks5AuthNone
	}
	if !containsByte(methods, method) {
		method = socks5AuthUnavailable
	}
	if _, err := conn.Write([]byte{socks5Version, method}); err != nil {
		return err
	}
	if method == socks5AuthUnavailable {
		return nil
	}

	observation := socks5Observation{}
	if method == socks5AuthUsernamePassword {
		if _, err := io.ReadFull(conn, header[:2]); err != nil {
			return err
		}
		if header[0] != socks5UserPassVersion || header[1] == 0 {
			return fmt.Errorf("invalid username/password request %x", header[:2])
		}
		username := make([]byte, int(header[1]))
		if _, err := io.ReadFull(conn, username); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, header[:1]); err != nil {
			return err
		}
		password := make([]byte, int(header[0]))
		if _, err := io.ReadFull(conn, password); err != nil {
			return err
		}
		observation.username = string(username)
		observation.password = string(password)
		accepted := server.options.acceptAnyCredentials ||
			(observation.username == server.options.username && observation.password == server.options.password)
		status := byte(0)
		if !accepted {
			status = 1
		}
		if _, err := conn.Write([]byte{socks5UserPassVersion, status}); err != nil {
			return err
		}
		if status != 0 {
			return nil
		}
	}

	if _, err := io.ReadFull(conn, header[:4]); err != nil {
		return err
	}
	if header[0] != socks5Version || header[1] != socks5CommandConnect || header[2] != 0 {
		return fmt.Errorf("invalid CONNECT request %x", header[:4])
	}
	observation.addressType = header[3]
	host, err := readSOCKS5Host(conn, header[3])
	if err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, header[:2]); err != nil {
		return err
	}
	observation.host = host
	observation.port = binary.BigEndian.Uint16(header[:2])
	select {
	case server.observations <- observation:
	default:
	}

	reply := server.options.reply
	if reply != 0 {
		_, err := conn.Write([]byte{socks5Version, reply, 0, socks5AddressIPv4, 0, 0, 0, 0, 0, 0})
		return err
	}
	target := server.options.targetOverride
	if target == "" {
		target = net.JoinHostPort(host, fmt.Sprint(observation.port))
	}
	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{socks5Version, 0x05, 0, socks5AddressIPv4, 0, 0, 0, 0, 0, 0})
		return nil
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{socks5Version, 0, 0, socks5AddressIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	server.connects.Add(1)
	_ = conn.SetDeadline(time.Time{})
	proxyTunnel(conn, upstream, bufio.NewReader(conn))
	return nil
}

func containsByte(values []byte, target byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func readSOCKS5Host(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case socks5AddressIPv4:
		buffer := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return "", err
		}
		return net.IP(buffer).String(), nil
	case socks5AddressIPv6:
		buffer := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return "", err
		}
		return net.IP(buffer).String(), nil
	case socks5AddressDomain:
		var size [1]byte
		if _, err := io.ReadFull(reader, size[:]); err != nil {
			return "", err
		}
		if size[0] == 0 {
			return "", errors.New("zero-length domain")
		}
		buffer := make([]byte, int(size[0]))
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return "", err
		}
		return string(buffer), nil
	default:
		return "", fmt.Errorf("unknown address type 0x%02x", addressType)
	}
}

func startPlainHTTPOrigin(t *testing.T) (net.Listener, *http.Server) {
	t.Helper()
	listener := listenCounting(t)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(writer, request.Proto)
	})}
	runServer(t, server, listener, func() error { return server.Serve(listener) })
	return listener, server
}

func TestSOCKS5HTTPAndGOSTHTTPS(t *testing.T) {
	for _, proxyScheme := range []string{"socks5", "socks5h"} {
		t.Run(proxyScheme+"/http", func(t *testing.T) {
			originListener, _ := startPlainHTTPOrigin(t)
			proxy := newSOCKS5TestServer(t, socks5TestOptions{targetOverride: originListener.Addr().String()})
			transport := NewTransport(nil)
			transport.Proxy = http.ProxyURL(proxy.URL(proxyScheme, nil))
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			requestURL := "http://server.test:" + portOf(t, originListener.Addr().String()) + "/"
			for range 2 {
				response, err := client.Get(requestURL)
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if readErr != nil {
					t.Fatal(readErr)
				}
				if response.ProtoMajor != 1 || string(body) != "HTTP/1.1" {
					t.Fatalf("protocol=%s body=%q", response.Proto, body)
				}
				if _, ok := ResponseConnectionState(response); ok {
					t.Fatal("plain HTTP response unexpectedly has TLS state")
				}
			}
			observation := <-proxy.observations
			if observation.addressType != socks5AddressDomain || observation.host != "server.test" {
				t.Fatalf("SOCKS target=%+v", observation)
			}
			if proxy.accepted.Load() != 1 || proxy.connects.Load() != 1 {
				t.Fatalf("accepted=%d connects=%d, want one tunnel", proxy.accepted.Load(), proxy.connects.Load())
			}
		})

		t.Run(proxyScheme+"/https", func(t *testing.T) {
			certificate, leaf := httpTestCertificate(t)
			originListener := listenCounting(t)
			origin := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				_, _ = io.WriteString(writer, request.Proto)
			})}
			serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
			runServer(t, origin, originListener, func() error { return ServeHTTP1(origin, originListener, serverConfig) })
			proxy := newSOCKS5TestServer(t, socks5TestOptions{targetOverride: originListener.Addr().String()})
			transport := NewHTTP1Transport(clientConfigForLeaf(leaf))
			transport.Proxy = http.ProxyURL(proxy.URL(proxyScheme, nil))
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			requestURL := "https://server.test:" + portOf(t, originListener.Addr().String()) + "/"
			response, err := client.Get(requestURL)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.ProtoMajor != 1 || string(body) != "HTTP/1.1" {
				t.Fatalf("protocol=%s body=%q", response.Proto, body)
			}
			if state, ok := ResponseConnectionState(response); !ok || !state.HandshakeComplete {
				t.Fatal("GOST TLS state is unavailable")
			}
			observation := <-proxy.observations
			if observation.addressType != socks5AddressDomain || observation.host != "server.test" {
				t.Fatalf("SOCKS target=%+v", observation)
			}
		})
	}
}

func TestSOCKS5HTTP2UsesOneTunnel(t *testing.T) {
	const parallelRequests = 8
	certificate, leaf := httpTestCertificate(t)
	originListener := listenCounting(t)
	var arrived atomic.Int64
	release := make(chan struct{})
	var releaseOnce sync.Once
	origin := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if arrived.Add(1) == parallelRequests {
			releaseOnce.Do(func() { close(release) })
		}
		select {
		case <-release:
		case <-request.Context().Done():
			return
		}
		_, _ = io.WriteString(writer, request.Proto)
	})}
	serverConfig := gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{certificate}})
	runServer(t, origin, originListener, func() error { return Serve(origin, originListener, serverConfig) })
	proxy := newSOCKS5TestServer(t, socks5TestOptions{targetOverride: originListener.Addr().String()})
	transport := NewTransport(clientConfigForLeaf(leaf))
	transport.Proxy = http.ProxyURL(proxy.URL("socks5", nil))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	requestURL := "https://server.test:" + portOf(t, originListener.Addr().String()) + "/"

	errorsCh := make(chan error, parallelRequests)
	var wait sync.WaitGroup
	for range parallelRequests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, err := client.Get(requestURL)
			if err == nil {
				var body []byte
				body, err = io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err == nil && (response.ProtoMajor != 2 || string(body) != "HTTP/2.0") {
					err = fmt.Errorf("protocol=%s body=%q", response.Proto, body)
				}
			}
			errorsCh <- err
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if proxy.accepted.Load() != 1 || proxy.connects.Load() != 1 || originListener.accepted.Load() != 1 {
		t.Fatalf(
			"proxy accepted=%d connects=%d origin accepted=%d, want one tunnel",
			proxy.accepted.Load(), proxy.connects.Load(), originListener.accepted.Load(),
		)
	}
}

func TestSOCKS5Authentication(t *testing.T) {
	t.Run("username-password", func(t *testing.T) {
		originListener, _ := startPlainHTTPOrigin(t)
		proxy := newSOCKS5TestServer(t, socks5TestOptions{
			targetOverride: originListener.Addr().String(),
			requireAuth:    true,
			username:       "alice",
			password:       "correct horse",
		})
		transport := NewTransport(nil)
		transport.Proxy = http.ProxyURL(proxy.URL("socks5", url.UserPassword("alice", "correct horse")))
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
		response, err := client.Get("http://server.test:" + portOf(t, originListener.Addr().String()) + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		observation := <-proxy.observations
		if observation.username != "alice" || observation.password != "correct horse" {
			t.Fatalf("credentials=%+v", observation)
		}
	})

	t.Run("server-selects-no-auth", func(t *testing.T) {
		originListener, _ := startPlainHTTPOrigin(t)
		proxy := newSOCKS5TestServer(t, socks5TestOptions{
			targetOverride: originListener.Addr().String(),
			preferNoAuth:   true,
		})
		transport := NewTransport(nil)
		transport.Proxy = http.ProxyURL(proxy.URL("socks5", url.UserPassword("alice", "unused")))
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
		response, err := client.Get("http://server.test:" + portOf(t, originListener.Addr().String()) + "/")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		observation := <-proxy.observations
		if observation.username != "" || observation.password != "" {
			t.Fatalf("proxy unexpectedly received credentials: %+v", observation)
		}
	})

	t.Run("rejected-without-secret-leak", func(t *testing.T) {
		proxy := newSOCKS5TestServer(t, socks5TestOptions{
			requireAuth: true,
			username:    "alice",
			password:    "expected",
		})
		transport := NewTransport(nil)
		transport.Proxy = http.ProxyURL(proxy.URL("socks5", url.UserPassword("alice", "do-not-leak")))
		transport.ProxyConnectTimeout = time.Second
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		_, err := client.Get("http://server.test/")
		if err == nil || !strings.Contains(err.Error(), "authentication failed") {
			t.Fatalf("authentication error=%v", err)
		}
		if strings.Contains(err.Error(), "do-not-leak") {
			t.Fatalf("authentication error leaked password: %v", err)
		}
	})
}

func TestSOCKS5PoolSeparatesCredentials(t *testing.T) {
	originListener, _ := startPlainHTTPOrigin(t)
	proxy := newSOCKS5TestServer(t, socks5TestOptions{
		targetOverride:       originListener.Addr().String(),
		requireAuth:          true,
		acceptAnyCredentials: true,
	})
	transport := NewTransport(nil)
	transport.Proxy = func(request *http.Request) (*url.URL, error) {
		proxyURL := proxy.URL("socks5", nil)
		proxyURL.User = url.UserPassword(request.Header.Get("X-Proxy-User"), request.Header.Get("X-Proxy-Password"))
		return proxyURL, nil
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	requestURL := "http://server.test:" + portOf(t, originListener.Addr().String()) + "/"
	for index, username := range []string{"alice", "bob"} {
		request, err := http.NewRequest(http.MethodGet, requestURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Proxy-User", username)
		request.Header.Set("X-Proxy-Password", fmt.Sprintf("secret-%d", index))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	if proxy.accepted.Load() != 2 || proxy.connects.Load() != 2 {
		t.Fatalf("accepted=%d connects=%d, want separate credential pools", proxy.accepted.Load(), proxy.connects.Load())
	}
}

func TestSOCKS5CredentialValidationAndPoolFingerprint(t *testing.T) {
	transport := NewTransport(nil)
	request, err := http.NewRequest(http.MethodGet, "https://server.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	invalidUsers := []*url.Userinfo{
		url.UserPassword("", "password"),
		url.UserPassword(strings.Repeat("u", 256), "password"),
		url.UserPassword("user", strings.Repeat("p", 256)),
	}
	for _, user := range invalidUsers {
		_, err := transport.routeForRequest(request, &url.URL{
			Scheme: "socks5",
			Host:   "proxy.test:1080",
			User:   user,
		})
		if err == nil || !strings.Contains(err.Error(), "username/password length") {
			t.Fatalf("invalid credentials error=%v", err)
		}
	}

	route, err := transport.routeForRequest(request, &url.URL{
		Scheme: "socks5",
		Host:   "proxy.test:1080",
		User:   url.UserPassword("alice", "do-not-leak"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if route.key.proxyAuth != credentialsFingerprint("alice", "do-not-leak") {
		t.Fatal("pool key does not contain the credential fingerprint")
	}
	if key := fmt.Sprint(route.key); strings.Contains(key, "alice") || strings.Contains(key, "do-not-leak") {
		t.Fatalf("pool key leaked credentials: %s", key)
	}
}

func TestSOCKS5ResolvesRouteOnceAndSkipsHTTPConnectCallbacks(t *testing.T) {
	originListener, _ := startPlainHTTPOrigin(t)
	proxy := newSOCKS5TestServer(t, socks5TestOptions{targetOverride: originListener.Addr().String()})
	transport := NewTransport(nil)
	var proxyCalls atomic.Int64
	var headerCalls atomic.Int64
	var responseCalls atomic.Int64
	transport.Proxy = func(*http.Request) (*url.URL, error) {
		proxyCalls.Add(1)
		return proxy.URL("socks5", nil), nil
	}
	transport.GetProxyConnectHeader = func(context.Context, *url.URL, string) (http.Header, error) {
		headerCalls.Add(1)
		return http.Header{"X-Must-Not-Be-Sent": []string{"true"}}, nil
	}
	transport.OnProxyConnectResponse = func(context.Context, *url.URL, *http.Request, *http.Response) error {
		responseCalls.Add(1)
		return nil
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("http://server.test:" + portOf(t, originListener.Addr().String()) + "/")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if proxyCalls.Load() != 1 || headerCalls.Load() != 0 || responseCalls.Load() != 0 {
		t.Fatalf(
			"proxy calls=%d header calls=%d response calls=%d",
			proxyCalls.Load(), headerCalls.Load(), responseCalls.Load(),
		)
	}
}

func TestSOCKS5ConnectError(t *testing.T) {
	proxy := newSOCKS5TestServer(t, socks5TestOptions{reply: 0x05})
	transport := NewTransport(nil)
	transport.Proxy = http.ProxyURL(proxy.URL("socks5", url.UserPassword("alice", "do-not-leak")))
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	_, err := client.Get("http://server.test/")
	if err == nil {
		t.Fatal("SOCKS5 failure unexpectedly succeeded")
	}
	var connectError *SOCKS5ConnectError
	if !errors.As(err, &connectError) {
		t.Fatalf("error %T does not contain SOCKS5ConnectError: %v", err, err)
	}
	if connectError.Reply != 0x05 || connectError.Target != "server.test:80" {
		t.Fatalf("connect error=%+v", connectError)
	}
	if strings.Contains(connectError.Proxy, "alice") || strings.Contains(connectError.Proxy, "do-not-leak") {
		t.Fatalf("connect error leaked credentials: %+v", connectError)
	}
}

func TestSOCKS5ProxyConnectTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		close(accepted)
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	transport := NewTransport(nil)
	transport.Proxy = http.ProxyURL(&url.URL{Scheme: "socks5", Host: listener.Addr().String()})
	transport.ProxyConnectTimeout = 100 * time.Millisecond
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	started := time.Now()
	_, err = client.Get("http://server.test/")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("SOCKS5 timeout took %v", elapsed)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("proxy did not accept connection")
	}
}

func TestSOCKS5ProtocolValidation(t *testing.T) {
	tests := []struct {
		name      string
		server    func(net.Conn) error
		wantError string
		proxyUser *url.Userinfo
	}{
		{
			name: "greeting version",
			server: func(conn net.Conn) error {
				if err := discardSOCKS5Greeting(conn); err != nil {
					return err
				}
				return writeAll(conn, []byte{4, socks5AuthNone})
			},
			wantError: "unexpected protocol version",
		},
		{
			name: "unsupported method",
			server: func(conn net.Conn) error {
				if err := discardSOCKS5Greeting(conn); err != nil {
					return err
				}
				return writeAll(conn, []byte{socks5Version, 0x7f})
			},
			wantError: "unsupported authentication method",
		},
		{
			name: "unoffered username password",
			server: func(conn net.Conn) error {
				if err := discardSOCKS5Greeting(conn); err != nil {
					return err
				}
				return writeAll(conn, []byte{socks5Version, socks5AuthUsernamePassword})
			},
			wantError: "was not offered",
		},
		{
			name: "authentication version",
			server: func(conn net.Conn) error {
				if err := discardSOCKS5Greeting(conn); err != nil {
					return err
				}
				if err := writeAll(conn, []byte{socks5Version, socks5AuthUsernamePassword}); err != nil {
					return err
				}
				if err := discardSOCKS5UserPass(conn); err != nil {
					return err
				}
				return writeAll(conn, []byte{2, 0})
			},
			wantError: "unexpected username/password version",
			proxyUser: url.UserPassword("user", "password"),
		},
		{
			name: "reply version",
			server: func(conn net.Conn) error {
				if err := acceptSOCKS5NoAuthAndReadConnect(conn); err != nil {
					return err
				}
				return writeAll(conn, []byte{4, 0, 0, socks5AddressIPv4})
			},
			wantError: "unexpected CONNECT reply version",
		},
		{
			name: "reserved field",
			server: func(conn net.Conn) error {
				if err := acceptSOCKS5NoAuthAndReadConnect(conn); err != nil {
					return err
				}
				return writeAll(conn, []byte{socks5Version, 0, 1, socks5AddressIPv4})
			},
			wantError: "non-zero CONNECT reserved field",
		},
		{
			name: "reply address type",
			server: func(conn net.Conn) error {
				if err := acceptSOCKS5NoAuthAndReadConnect(conn); err != nil {
					return err
				}
				return writeAll(conn, []byte{socks5Version, 0, 0, 0x7f})
			},
			wantError: "unknown CONNECT address type",
		},
		{
			name: "truncated reply",
			server: func(conn net.Conn) error {
				if err := acceptSOCKS5NoAuthAndReadConnect(conn); err != nil {
					return err
				}
				return writeAll(conn, []byte{socks5Version, 0, 0, socks5AddressIPv6, 0})
			},
			wantError: "read CONNECT bound address",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
			_ = serverConn.SetDeadline(time.Now().Add(2 * time.Second))
			serverError := make(chan error, 1)
			go func() {
				defer serverConn.Close()
				serverError <- test.server(serverConn)
			}()
			proxyURL := &url.URL{Scheme: "socks5", Host: "proxy.test:1080", User: test.proxyUser}
			err := socks5Connect(context.Background(), clientConn, proxyURL, "server.test:443")
			_ = clientConn.Close()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error=%v, want substring %q", err, test.wantError)
			}
			if scriptErr := <-serverError; scriptErr != nil {
				t.Fatal(scriptErr)
			}
		})
	}
}

func TestSOCKS5CancellationAtEachPhase(t *testing.T) {
	tests := []struct {
		name      string
		proxyUser *url.Userinfo
		server    func(net.Conn) error
	}{
		{
			name: "method selection",
			server: func(conn net.Conn) error {
				return discardSOCKS5Greeting(conn)
			},
		},
		{
			name:      "authentication",
			proxyUser: url.UserPassword("user", "password"),
			server: func(conn net.Conn) error {
				if err := discardSOCKS5Greeting(conn); err != nil {
					return err
				}
				if err := writeAll(conn, []byte{socks5Version, socks5AuthUsernamePassword}); err != nil {
					return err
				}
				return discardSOCKS5UserPass(conn)
			},
		},
		{
			name: "CONNECT reply",
			server: func(conn net.Conn) error {
				return acceptSOCKS5NoAuthAndReadConnect(conn)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			serverDone := make(chan error, 1)
			go func() {
				defer serverConn.Close()
				serverDone <- test.server(serverConn)
				_, _ = io.Copy(io.Discard, serverConn)
			}()
			transport := NewTransport(nil)
			transport.ProxyConnectTimeout = 50 * time.Millisecond
			route := dialRoute{
				targetAddr: "server.test:443",
				proxyURL: &url.URL{
					Scheme: "socks5",
					Host:   "proxy.test:1080",
					User:   test.proxyUser,
				},
			}
			err := transport.connectSOCKS5(context.Background(), clientConn, route)
			_ = clientConn.Close()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancellation error=%v", err)
			}
			if scriptErr := <-serverDone; scriptErr != nil {
				t.Fatal(scriptErr)
			}
		})
	}
}

func TestSOCKS5SuccessfulHandshakeClearsDeadline(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		if err := acceptSOCKS5NoAuthAndReadConnect(serverConn); err != nil {
			serverDone <- err
			return
		}
		if err := writeAll(serverConn, []byte{socks5Version, 0, 0, socks5AddressIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
			serverDone <- err
			return
		}
		var echo [1]byte
		if _, err := io.ReadFull(serverConn, echo[:]); err != nil {
			serverDone <- err
			return
		}
		_, err := serverConn.Write(echo[:])
		serverDone <- err
	}()
	transport := NewTransport(nil)
	transport.ProxyConnectTimeout = 50 * time.Millisecond
	route := dialRoute{
		targetAddr: "server.test:443",
		proxyURL:   &url.URL{Scheme: "socks5", Host: "proxy.test:1080"},
	}
	if err := transport.connectSOCKS5(context.Background(), clientConn, route); err != nil {
		t.Fatal(err)
	}
	time.Sleep(75 * time.Millisecond)
	if _, err := clientConn.Write([]byte{0x42}); err != nil {
		t.Fatalf("deadline was not cleared: %v", err)
	}
	var echo [1]byte
	if _, err := io.ReadFull(clientConn, echo[:]); err != nil || echo[0] != 0x42 {
		t.Fatalf("echo=%x err=%v", echo, err)
	}
	_ = clientConn.Close()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func discardSOCKS5Greeting(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != socks5Version || header[1] == 0 {
		return fmt.Errorf("invalid greeting %x", header)
	}
	_, err := io.CopyN(io.Discard, conn, int64(header[1]))
	return err
}

func discardSOCKS5UserPass(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != socks5UserPassVersion || header[1] == 0 {
		return fmt.Errorf("invalid username/password header %x", header)
	}
	if _, err := io.CopyN(io.Discard, conn, int64(header[1])); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, header[:1]); err != nil {
		return err
	}
	_, err := io.CopyN(io.Discard, conn, int64(header[0]))
	return err
}

func acceptSOCKS5NoAuthAndReadConnect(conn net.Conn) error {
	if err := discardSOCKS5Greeting(conn); err != nil {
		return err
	}
	if err := writeAll(conn, []byte{socks5Version, socks5AuthNone}); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != socks5Version || header[1] != socks5CommandConnect || header[2] != 0 {
		return fmt.Errorf("invalid CONNECT request %x", header)
	}
	if _, err := readSOCKS5Host(conn, header[3]); err != nil {
		return err
	}
	_, err := io.CopyN(io.Discard, conn, 2)
	return err
}

func TestAppendSOCKS5Address(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		addressType byte
		wireHost    string
	}{
		{name: "IPv4", address: "192.0.2.1:443", addressType: socks5AddressIPv4},
		{name: "IPv6", address: "[2001:db8::1]:443", addressType: socks5AddressIPv6},
		{name: "remote IDNA", address: "пример.рф:443", addressType: socks5AddressDomain, wireHost: "xn--e1afmkfd.xn--p1ai"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buffer, err := appendSOCKS5Address(make([]byte, 0, 300), test.address)
			if err != nil {
				t.Fatal(err)
			}
			if buffer[0] != test.addressType {
				t.Fatalf("address type=0x%02x", buffer[0])
			}
			if test.wireHost != "" {
				size := int(buffer[1])
				if host := string(buffer[2 : 2+size]); host != test.wireHost {
					t.Fatalf("wire hostname=%q", host)
				}
			}
		})
	}
}

func TestSOCKS5ReplyText(t *testing.T) {
	for reply := byte(1); reply <= 8; reply++ {
		if text := socks5ReplyText(reply); text == "" || strings.Contains(text, "unknown") {
			t.Fatalf("reply 0x%02x text=%q", reply, text)
		}
	}
	if text := socks5ReplyText(0xfe); !strings.Contains(text, "0xfe") {
		t.Fatalf("unknown reply text=%q", text)
	}
}

func portOf(t testing.TB, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	return port
}
