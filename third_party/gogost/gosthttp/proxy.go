package gosthttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	"golang.org/x/net/idna"
)

const defaultMaxResponseHeaderBytes int64 = 10 << 20

// A pool never spans Transport instances, so the immutable origin/proxy TLS
// profiles are already part of its namespace. The remaining per-request route
// inputs, including the complete CONNECT header set, are captured here.
type routeKey struct {
	targetScheme string
	targetAddr   string
	proxyScheme  string
	proxyAddr    string
	proxyAuth    [sha256.Size]byte
}

type dialRoute struct {
	key           routeKey
	targetScheme  string
	targetAddr    string
	targetName    string
	proxyURL      *url.URL
	connectHeader http.Header
}

// ProxyConnectError describes a non-200 response to a CONNECT request.
type ProxyConnectError struct {
	Proxy      string
	Target     string
	StatusCode int
	Status     string
	Header     http.Header
}

func (e *ProxyConnectError) Error() string {
	return fmt.Sprintf("gosthttp: proxy CONNECT %s via %s failed: %s", e.Target, e.Proxy, e.Status)
}

func canonicalRequestAddress(requestURL *url.URL) (addr, name, scheme string, err error) {
	if requestURL == nil {
		return "", "", "", errors.New("gosthttp: nil request URL")
	}
	scheme = strings.ToLower(requestURL.Scheme)
	var defaultPort string
	switch scheme {
	case "http":
		defaultPort = "80"
	case "https":
		defaultPort = "443"
	default:
		return "", "", "", fmt.Errorf("gosthttp: unsupported protocol scheme %q", requestURL.Scheme)
	}
	name = requestURL.Hostname()
	if name == "" {
		return "", "", "", errors.New("gosthttp: request has no host")
	}
	if _, parseErr := netip.ParseAddr(name); parseErr != nil && !strings.Contains(name, "%") {
		asciiName, err := idna.Lookup.ToASCII(name)
		if err != nil {
			return "", "", "", fmt.Errorf("gosthttp: invalid request hostname %q: %w", name, err)
		}
		name = asciiName
	}
	port := requestURL.Port()
	if port == "" {
		port = defaultPort
	} else if host, explicitPort, splitErr := net.SplitHostPort(requestURL.Host); splitErr == nil && host == name && explicitPort == port {
		// Reuse the URL's immutable host storage on the overwhelmingly common
		// explicit-port path instead of allocating an identical string.
		return requestURL.Host, name, scheme, nil
	}
	return net.JoinHostPort(name, port), name, scheme, nil
}

func canonicalProxyAddress(proxyURL *url.URL) (string, error) {
	host := proxyURL.Hostname()
	if host == "" {
		return "", errors.New("gosthttp: proxy URL has no host")
	}
	if _, parseErr := netip.ParseAddr(host); parseErr != nil && !strings.Contains(host, "%") {
		asciiHost, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("gosthttp: invalid proxy hostname %q: %w", host, err)
		}
		host = asciiHost
	}
	port := proxyURL.Port()
	if port == "" {
		switch proxyURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		default:
			return "", fmt.Errorf("gosthttp: unsupported proxy scheme %q", proxyURL.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}

func cloneURL(value *url.URL) *url.URL {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func normalizeProxyURL(value *url.URL) (*url.URL, error) {
	if value == nil {
		return nil, nil
	}
	proxyURL := cloneURL(value)
	proxyURL.Scheme = strings.ToLower(proxyURL.Scheme)
	if proxyURL.Scheme == "" {
		proxyURL.Scheme = "http"
	}
	switch proxyURL.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("gosthttp: unsupported proxy scheme %q", proxyURL.Scheme)
	}
	return proxyURL, nil
}

func cloneHeader(value http.Header) http.Header {
	if value == nil {
		return make(http.Header)
	}
	return value.Clone()
}

func basicProxyAuthorization(user *url.Userinfo) string {
	if user == nil {
		return ""
	}
	password, _ := user.Password()
	token := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
	return "Basic " + token
}

func headerFingerprint(header http.Header) [sha256.Size]byte {
	h := sha256.New()
	rawKeys := make([]string, 0, len(header))
	for key := range header {
		rawKeys = append(rawKeys, key)
	}
	canonicalKey := func(key string) string {
		canonical := http.CanonicalHeaderKey(key)
		if canonical == "" {
			// Request.Write rejects invalid names later, but keep them distinct
			// in the pool key until that happens.
			return key
		}
		return canonical
	}
	sort.Slice(rawKeys, func(i, j int) bool {
		left, right := canonicalKey(rawKeys[i]), canonicalKey(rawKeys[j])
		if left != right {
			return left < right
		}
		return rawKeys[i] < rawKeys[j]
	})
	normalized := make(map[string][]string, len(header))
	for _, key := range rawKeys {
		canonical := canonicalKey(key)
		normalized[canonical] = append(normalized[canonical], header[key]...)
	}
	keys := make([]string, 0, len(normalized))
	for key := range normalized {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var size [4]byte
	write := func(value string) {
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = h.Write(size[:])
		_, _ = io.WriteString(h, value)
	}
	for _, key := range keys {
		write(key)
		values := append([]string(nil), normalized[key]...)
		binary.BigEndian.PutUint32(size[:], uint32(len(values)))
		_, _ = h.Write(size[:])
		for _, value := range values {
			write(value)
		}
	}
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

func credentialsFingerprint(username, password string) [sha256.Size]byte {
	var input [2*4 + 2*255]byte
	offset := 0
	binary.BigEndian.PutUint32(input[offset:offset+4], uint32(len(username)))
	offset += 4
	offset += copy(input[offset:], username)
	binary.BigEndian.PutUint32(input[offset:offset+4], uint32(len(password)))
	offset += 4
	offset += copy(input[offset:], password)
	return sha256.Sum256(input[:offset])
}

func (t *Transport) proxyForRequest(request *http.Request) (*url.URL, error) {
	if t.Proxy == nil {
		return nil, nil
	}
	proxyURL, err := t.Proxy(request)
	if err != nil {
		return nil, err
	}
	return normalizeProxyURL(proxyURL)
}

func (t *Transport) routeForRequest(request *http.Request, proxyURL *url.URL) (dialRoute, error) {
	targetAddr, targetName, targetScheme, err := canonicalRequestAddress(request.URL)
	if err != nil {
		return dialRoute{}, err
	}
	route := dialRoute{
		targetScheme: targetScheme,
		targetAddr:   targetAddr,
		targetName:   targetName,
		key: routeKey{
			targetScheme: targetScheme,
			targetAddr:   targetAddr,
		},
	}
	if proxyURL == nil {
		return route, nil
	}
	proxyAddr, err := canonicalProxyAddress(proxyURL)
	if err != nil {
		return dialRoute{}, err
	}

	route.proxyURL = cloneURL(proxyURL)
	route.key.proxyScheme = proxyURL.Scheme
	route.key.proxyAddr = proxyAddr
	if isSOCKS5Proxy(proxyURL) {
		username, password, hasCredentials, err := socks5Credentials(proxyURL.User)
		if err != nil {
			return dialRoute{}, err
		}
		if hasCredentials {
			route.key.proxyAuth = credentialsFingerprint(username, password)
		}
		return route, nil
	}

	var header http.Header
	if t.GetProxyConnectHeader != nil {
		header, err = t.GetProxyConnectHeader(request.Context(), cloneURL(proxyURL), targetAddr)
		if err != nil {
			return dialRoute{}, err
		}
	} else {
		header = t.ProxyConnectHeader
	}
	header = cloneHeader(header)
	if authorization := basicProxyAuthorization(proxyURL.User); authorization != "" {
		header.Set("Proxy-Authorization", authorization)
	}
	route.connectHeader = header
	route.key.proxyAuth = headerFingerprint(header)
	return route, nil
}

func (t *Transport) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.ConnectStart != nil {
		trace.ConnectStart(network, addr)
	}
	var (
		conn net.Conn
		err  error
	)
	if t.DialContext != nil {
		conn, err = t.DialContext(ctx, network, addr)
	} else {
		var dialer net.Dialer
		conn, err = dialer.DialContext(ctx, network, addr)
	}
	if trace != nil && trace.ConnectDone != nil {
		trace.ConnectDone(network, addr, err)
	}
	if conn == nil && err == nil {
		err = errors.New("gosthttp: DialContext returned (nil, nil)")
	}
	return conn, err
}

func handshakeContext(ctx context.Context, timeout time.Duration, conn *gosttls.Conn) error {
	if timeout <= 0 {
		return conn.HandshakeContext(ctx)
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return conn.HandshakeContext(handshakeCtx)
}

func (t *Transport) dialRoute(ctx context.Context, route dialRoute) (net.Conn, error) {
	if route.proxyURL == nil {
		return t.dialContext(ctx, "tcp", route.targetAddr)
	}
	conn, err := t.dialContext(ctx, "tcp", route.key.proxyAddr)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()

	if isSOCKS5Proxy(route.proxyURL) {
		if err := t.connectSOCKS5(ctx, conn, route); err != nil {
			return nil, err
		}
		closeOnError = false
		return conn, nil
	}

	if route.proxyURL.Scheme == "https" {
		config := t.ProxyTLSClientConfig
		if config == nil {
			config = new(gosttls.Config)
		}
		config = config.Clone()
		if config.ServerName == "" {
			config.ServerName = route.proxyURL.Hostname()
		}
		config.NextProtos = []string{"http/1.1"}
		secureProxy := gosttls.Client(conn, config)
		if err := handshakeContext(ctx, t.ProxyTLSHandshakeTimeout, secureProxy); err != nil {
			return nil, fmt.Errorf("gosthttp: HTTPS proxy TLS handshake: %w", err)
		}
		conn = secureProxy
	}

	tunneled, err := t.connectTunnel(ctx, conn, route)
	if err != nil {
		return nil, err
	}
	conn = tunneled
	closeOnError = false
	return conn, nil
}

func (t *Transport) connectTunnel(ctx context.Context, conn net.Conn, route dialRoute) (net.Conn, error) {
	connectCtx, cleanup := proxyOperationContext(ctx, t.ProxyConnectTimeout, conn)
	defer cleanup()

	connectRequest := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: route.targetAddr},
		Host:   route.targetAddr,
		Header: cloneHeader(route.connectHeader),
	}
	if err := connectRequest.Write(conn); err != nil {
		if connectCtx.Err() != nil {
			return nil, connectCtx.Err()
		}
		return nil, err
	}
	limit := t.MaxResponseHeaderBytes
	if limit <= 0 {
		limit = defaultMaxResponseHeaderBytes
	}
	limited := &io.LimitedReader{R: conn, N: limit + 1}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, connectRequest)
	if err != nil {
		if connectCtx.Err() != nil {
			return nil, connectCtx.Err()
		}
		if limited.N <= 0 {
			return nil, errors.New("gosthttp: proxy CONNECT response headers exceeded limit")
		}
		return nil, err
	}
	if t.OnProxyConnectResponse != nil {
		if err := t.OnProxyConnectResponse(connectCtx, cloneURL(route.proxyURL), connectRequest, response); err != nil {
			return nil, err
		}
	}
	if response.StatusCode != http.StatusOK {
		return nil, &ProxyConnectError{
			Proxy:      sanitizedProxyString(route.proxyURL),
			Target:     route.targetAddr,
			StatusCode: response.StatusCode,
			Status:     response.Status,
			Header:     response.Header.Clone(),
		}
	}
	if reader.Buffered() == 0 {
		return conn, nil
	}
	prefix := make([]byte, reader.Buffered())
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return nil, err
	}
	return &bufferedConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(prefix), conn)}, nil
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}
