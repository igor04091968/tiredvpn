package gosthttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
)

var errBridgeConnAlreadyUsed = errors.New("gosthttp: internal connection bridge used more than once")

type selectedProxyKey struct{}

type selectedProxy struct {
	url *url.URL
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, errors.New("gosthttp: nil *http.Request")
	}
	if request.URL == nil {
		return nil, errors.New("gosthttp: nil Request.URL")
	}
	if err := t.initialize(); err != nil {
		return nil, err
	}

	scheme := strings.ToLower(request.URL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("gosthttp: unsupported protocol scheme %q", request.URL.Scheme)
	}
	proxyURL, err := t.proxyForRequest(request)
	if err != nil {
		return nil, err
	}

	switch scheme {
	case "http":
		if !isSOCKS5Proxy(proxyURL) {
			plainRequest := request.WithContext(context.WithValue(
				request.Context(),
				selectedProxyKey{},
				selectedProxy{url: cloneURL(proxyURL)},
			))
			response, err := t.state.plain.RoundTrip(plainRequest)
			if response != nil {
				response.Request = request
			}
			return response, err
		}
		route, err := t.routeForRequest(request, proxyURL)
		if err != nil {
			return nil, err
		}
		return t.roundTripRoute(request, route)
	case "https":
		route, err := t.routeForRequest(request, proxyURL)
		if err != nil {
			return nil, err
		}
		return t.roundTripRoute(request, route)
	}
	panic("unreachable")
}

func (t *Transport) roundTripRoute(request *http.Request, route dialRoute) (*http.Response, error) {
	var firstErr error
	for attempt := 0; attempt < 2; attempt++ {
		trace := httptrace.ContextClientTrace(request.Context())
		if trace != nil && trace.GetConn != nil {
			trace.GetConn(route.targetAddr)
		}
		acquired, err := t.acquireConn(request.Context(), route)
		if err != nil {
			if firstErr != nil {
				return nil, firstErr
			}
			return nil, err
		}
		if trace != nil && trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{
				Conn:     acquired.conn.netConn,
				Reused:   acquired.reused,
				WasIdle:  acquired.wasIdle,
				IdleTime: acquired.idleTime,
			})
		}

		attemptContext := request.Context()
		if acquired.conn.tlsState != nil {
			attemptContext = contextWithConnectionState(attemptContext, acquired.conn.tlsState)
		}
		attemptRequest := request.WithContext(attemptContext)
		if attempt > 0 && request.Body != nil && request.Body != http.NoBody {
			body, bodyErr := request.GetBody()
			if bodyErr != nil {
				acquired.conn.client.Release()
				return nil, firstErr
			}
			attemptRequest.Body = body
		}
		response, roundTripErr := acquired.conn.client.RoundTrip(attemptRequest)
		t.signalPoolEvent()
		if roundTripErr == nil {
			if t.DisableKeepAlives && response.Body != nil {
				response.Body = &closeConnBody{
					ReadCloser: response.Body,
					closeConn:  acquired.conn.client.Close,
				}
			}
			if response.Body != nil && acquired.conn.protocol == "h2" {
				response.Body = &poolEventBody{
					ReadCloser: response.Body,
					transport:  t,
				}
			}
			return response, nil
		}

		if firstErr == nil {
			firstErr = roundTripErr
		}
		if attempt != 0 || !acquired.reused || !requestReplayable(request) {
			return nil, roundTripErr
		}
		// A reused connection which fails before producing a response may have
		// become stale while idle. Retire it before the single safe replay.
		t.discardConn(acquired.conn)
	}
	return nil, firstErr
}

func requestReplayable(request *http.Request) bool {
	if request == nil {
		return false
	}
	if request.Body != nil && request.Body != http.NoBody && request.GetBody == nil {
		return false
	}
	method := request.Method
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	_, hasIdempotencyKey := request.Header["Idempotency-Key"]
	_, hasLegacyIdempotencyKey := request.Header["X-Idempotency-Key"]
	return hasIdempotencyKey || hasLegacyIdempotencyKey
}

func (t *Transport) initialize() error {
	t.state.once.Do(func() {
		plainProtocols := new(http.Protocols)
		plainProtocols.SetHTTP1(true)
		plainProxy := func(request *http.Request) (*url.URL, error) {
			if selection, ok := request.Context().Value(selectedProxyKey{}).(selectedProxy); ok {
				return cloneURL(selection.url), nil
			}
			// Keep the internal transport safe if it is ever used without the
			// normal RoundTrip dispatcher.
			return t.proxyForRequest(request)
		}
		t.state.plain = &http.Transport{
			Proxy:                  plainProxy,
			OnProxyConnectResponse: t.OnProxyConnectResponse,
			DialContext:            t.DialContext,
			DisableKeepAlives:      t.DisableKeepAlives,
			DisableCompression:     t.DisableCompression,
			MaxIdleConns:           t.MaxIdleConns,
			MaxIdleConnsPerHost:    t.MaxIdleConnsPerHost,
			MaxConnsPerHost:        t.MaxConnsPerHost,
			IdleConnTimeout:        t.IdleConnTimeout,
			ResponseHeaderTimeout:  t.ResponseHeaderTimeout,
			ExpectContinueTimeout:  t.ExpectContinueTimeout,
			ProxyConnectHeader:     cloneHeader(t.ProxyConnectHeader),
			GetProxyConnectHeader:  t.GetProxyConnectHeader,
			MaxResponseHeaderBytes: t.MaxResponseHeaderBytes,
			WriteBufferSize:        t.WriteBufferSize,
			ReadBufferSize:         t.ReadBufferSize,
			Protocols:              plainProtocols,
		}
		t.state.groups = make(map[routeKey]*connGroup)
		t.state.events = make(chan struct{}, 1)
		t.state.connHook = func(*http.ClientConn) { t.signalPoolEvent() }
	})
	return t.state.initErr
}

func (t *Transport) enabledProtocols() (http1, http2 bool) {
	if t.Protocols == nil {
		return true, true
	}
	return t.Protocols.HTTP1(), t.Protocols.HTTP2()
}

func (t *Transport) originTLSConfig(route dialRoute) (*gosttls.Config, error) {
	config := t.TLSClientConfig
	if config == nil {
		config = new(gosttls.Config)
	}
	config = config.Clone()
	if config.ServerName == "" {
		config.ServerName = route.targetName
	}
	http1, http2 := t.enabledProtocols()
	if !http1 && !http2 {
		return nil, errors.New("gosthttp: neither HTTP/1.1 nor HTTP/2 is enabled")
	}
	config.NextProtos = nil
	if http2 {
		config.NextProtos = append(config.NextProtos, "h2")
	}
	if http1 {
		config.NextProtos = append(config.NextProtos, "http/1.1")
	}
	return config, nil
}

func (t *Transport) dialClientConn(ctx context.Context, route dialRoute) (*pooledConn, error) {
	rawConn, err := t.dialRoute(ctx, route)
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = rawConn.Close()
		}
	}()
	if route.targetScheme == "http" {
		client, err := t.newBridgedClientConn(ctx, route.targetAddr, "http/1.1", rawConn)
		if err != nil {
			return nil, err
		}
		pooled := &pooledConn{
			client:   client,
			netConn:  rawConn,
			protocol: "http/1.1",
		}
		if err := client.Reserve(); err != nil {
			_ = client.Close()
			return nil, err
		}
		pooled.uses = 1
		closeOnError = false
		return pooled, nil
	}
	if route.targetScheme != "https" {
		return nil, fmt.Errorf("gosthttp: unsupported route scheme %q", route.targetScheme)
	}

	config, err := t.originTLSConfig(route)
	if err != nil {
		return nil, err
	}
	secureConn := gosttls.Client(rawConn, config)
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
	err = handshakeContext(ctx, t.TLSHandshakeTimeout, secureConn)
	if err != nil {
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tls.ConnectionState{}, err)
		}
		return nil, err
	}
	tlsState := secureConn.ConnectionState()
	if trace != nil && trace.TLSHandshakeDone != nil {
		// crypto/tls.ConnectionState cannot represent gostx509 chains. Report
		// completion without manufacturing a partial standard-library state;
		// callers can use ResponseConnectionState for the complete value.
		trace.TLSHandshakeDone(tls.ConnectionState{}, nil)
	}

	protocol, err := t.protocolForALPN(tlsState.NegotiatedProtocol)
	if err != nil {
		return nil, err
	}
	client, err := t.newBridgedClientConn(ctx, route.targetAddr, protocol, secureConn)
	if err != nil {
		return nil, err
	}
	pooled := &pooledConn{
		client:   client,
		netConn:  secureConn,
		tlsState: &tlsState,
		protocol: protocol,
	}
	if err := client.Reserve(); err != nil {
		_ = client.Close()
		return nil, err
	}
	pooled.uses = 1
	closeOnError = false
	return pooled, nil
}

func (t *Transport) protocolForALPN(alpn string) (string, error) {
	http1, http2 := t.enabledProtocols()
	switch alpn {
	case "h2":
		if !http2 {
			return "", errors.New("gosthttp: server selected disabled ALPN protocol h2")
		}
		return "h2", nil
	case "", "http/1.1":
		if !http1 {
			if alpn == "" {
				return "", errors.New("gosthttp: server did not negotiate h2 and HTTP/1.1 is disabled")
			}
			return "", errors.New("gosthttp: server selected disabled ALPN protocol http/1.1")
		}
		return "http/1.1", nil
	default:
		return "", fmt.Errorf("gosthttp: unsupported negotiated ALPN protocol %q", alpn)
	}
}

func (t *Transport) newBridgedClientConn(ctx context.Context, address, protocol string, conn net.Conn) (*http.ClientConn, error) {
	protocols := new(http.Protocols)
	switch protocol {
	case "h2":
		protocols.SetUnencryptedHTTP2(true)
	case "http/1.1":
		protocols.SetHTTP1(true)
	default:
		return nil, fmt.Errorf("gosthttp: cannot bridge application protocol %q", protocol)
	}

	var dialMu sync.Mutex
	used := false
	bridgeTransport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialMu.Lock()
			defer dialMu.Unlock()
			if used {
				return nil, errBridgeConnAlreadyUsed
			}
			used = true
			return conn, nil
		},
		DisableKeepAlives:      t.DisableKeepAlives,
		DisableCompression:     t.DisableCompression,
		ResponseHeaderTimeout:  t.ResponseHeaderTimeout,
		ExpectContinueTimeout:  t.ExpectContinueTimeout,
		MaxResponseHeaderBytes: t.MaxResponseHeaderBytes,
		WriteBufferSize:        t.WriteBufferSize,
		ReadBufferSize:         t.ReadBufferSize,
		Protocols:              protocols,
		HTTP2:                  cloneHTTP2Config(t.HTTP2),
	}
	return bridgeTransport.NewClientConn(ctx, "http", address)
}

// Clone returns a deep copy of t's exported fields and an empty connection
// pool. As with net/http.Transport, Clone must not be called concurrently with
// mutation of those fields.
func (t *Transport) Clone() *Transport {
	clone := &Transport{
		Proxy:                    t.Proxy,
		OnProxyConnectResponse:   t.OnProxyConnectResponse,
		DialContext:              t.DialContext,
		TLSHandshakeTimeout:      t.TLSHandshakeTimeout,
		ProxyTLSHandshakeTimeout: t.ProxyTLSHandshakeTimeout,
		ProxyConnectTimeout:      t.ProxyConnectTimeout,
		DisableKeepAlives:        t.DisableKeepAlives,
		DisableCompression:       t.DisableCompression,
		MaxIdleConns:             t.MaxIdleConns,
		MaxIdleConnsPerHost:      t.MaxIdleConnsPerHost,
		MaxConnsPerHost:          t.MaxConnsPerHost,
		IdleConnTimeout:          t.IdleConnTimeout,
		ResponseHeaderTimeout:    t.ResponseHeaderTimeout,
		ExpectContinueTimeout:    t.ExpectContinueTimeout,
		ProxyConnectHeader:       cloneHeader(t.ProxyConnectHeader),
		GetProxyConnectHeader:    t.GetProxyConnectHeader,
		MaxResponseHeaderBytes:   t.MaxResponseHeaderBytes,
		WriteBufferSize:          t.WriteBufferSize,
		ReadBufferSize:           t.ReadBufferSize,
		HTTP2:                    cloneHTTP2Config(t.HTTP2),
	}
	if t.TLSClientConfig != nil {
		clone.TLSClientConfig = t.TLSClientConfig.Clone()
	}
	if t.ProxyTLSClientConfig != nil {
		clone.ProxyTLSClientConfig = t.ProxyTLSClientConfig.Clone()
	}
	if t.Protocols != nil {
		clone.Protocols = new(http.Protocols)
		*clone.Protocols = *t.Protocols
	}
	return clone
}

func cloneHTTP2Config(config *http.HTTP2Config) *http.HTTP2Config {
	if config == nil {
		return nil
	}
	clone := new(http.HTTP2Config)
	*clone = *config
	return clone
}

type closeConnBody struct {
	io.ReadCloser
	closeOnce sync.Once
	closeConn func() error
}

type poolEventBody struct {
	io.ReadCloser
	once      sync.Once
	transport *Transport
}

func (b *poolEventBody) Read(buffer []byte) (int, error) {
	n, err := b.ReadCloser.Read(buffer)
	if err != nil {
		b.signal()
	}
	return n, err
}

func (b *poolEventBody) Close() error {
	err := b.ReadCloser.Close()
	b.signal()
	return err
}

func (b *poolEventBody) signal() {
	b.once.Do(b.transport.signalPoolEvent)
}

func (b *closeConnBody) Read(buffer []byte) (int, error) {
	n, err := b.ReadCloser.Read(buffer)
	if errors.Is(err, io.EOF) {
		b.close()
	}
	return n, err
}

func (b *closeConnBody) Close() error {
	err := b.ReadCloser.Close()
	b.close()
	return err
}

func (b *closeConnBody) close() {
	b.closeOnce.Do(func() { _ = b.closeConn() })
}

// The compiler checks the public contract here.
var _ http.RoundTripper = (*Transport)(nil)
