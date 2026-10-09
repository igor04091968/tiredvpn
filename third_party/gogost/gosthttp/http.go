// Package gosthttp integrates gosttls with net/http without replacing the Go
// toolchain. HTTPS connections support HTTP/1.1 and HTTP/2 selected by ALPN,
// including tunnels through HTTP, HTTPS, SOCKS5, and SOCKS5H proxies.
package gosthttp

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
)

// Dialer establishes direct GOST-capable TLS connections. Proxy-aware HTTP
// clients should use Transport instead.
type Dialer struct {
	NetDialer *net.Dialer
	TLSConfig *gosttls.Config
}

func (d *Dialer) netDialer() *net.Dialer {
	if d != nil && d.NetDialer != nil {
		return d.NetDialer
	}
	return new(net.Dialer)
}

// DialTLSContext matches http.Transport.DialTLSContext.
func (d *Dialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	tlsDialer := gosttls.Dialer{NetDialer: d.netDialer()}
	if d != nil {
		tlsDialer.Config = d.TLSConfig
	}
	return tlsDialer.DialContext(ctx, network, addr)
}

// Transport is a concurrent-safe HTTP RoundTripper using gosttls for HTTPS.
// Its exported fields must not be modified after the first RoundTrip call.
//
// The zero value is usable for direct HTTPS. NewTransport supplies defaults
// matching http.DefaultTransport and enables environment proxy discovery.
type Transport struct {
	// Proxy selects an HTTP, HTTPS, SOCKS5, or SOCKS5H proxy. SOCKS5 and
	// SOCKS5H both delegate hostname resolution to the proxy, matching Go
	// 1.27.1. A nil URL selects a direct connection.
	Proxy func(*http.Request) (*url.URL, error)

	// OnProxyConnectResponse is called only for HTTP/HTTPS CONNECT proxies.
	OnProxyConnectResponse func(
		ctx context.Context,
		proxyURL *url.URL,
		connectReq *http.Request,
		connectRes *http.Response,
	) error

	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	TLSClientConfig      *gosttls.Config
	ProxyTLSClientConfig *gosttls.Config

	TLSHandshakeTimeout      time.Duration
	ProxyTLSHandshakeTimeout time.Duration
	// ProxyConnectTimeout bounds HTTP CONNECT and the complete SOCKS5
	// negotiation. A zero value applies only the request context deadline.
	ProxyConnectTimeout time.Duration

	DisableKeepAlives  bool
	DisableCompression bool

	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
	IdleConnTimeout     time.Duration

	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration

	// ProxyConnectHeader and GetProxyConnectHeader apply only to HTTP/HTTPS
	// CONNECT proxies. SOCKS5 authentication is taken from proxy URL userinfo.
	ProxyConnectHeader    http.Header
	GetProxyConnectHeader func(ctx context.Context, proxyURL *url.URL, target string) (http.Header, error)

	MaxResponseHeaderBytes int64
	WriteBufferSize        int
	ReadBufferSize         int

	// Protocols controls HTTPS application protocols. A nil value enables
	// HTTP/1.1 and HTTP/2. UnencryptedHTTP2 is not exposed on the wire.
	Protocols *http.Protocols
	HTTP2     *http.HTTP2Config

	state transportState
}

// NewTransport returns an automatic HTTP/1.1 and HTTP/2 transport. If config
// is nil, the mixed GOST-first profile and a 128-entry session cache are used.
// Use gosttls.GOSTConfig for a strict RFC 9367-only endpoint. A non-nil
// configuration is cloned without changing its session policy.
func NewTransport(config *gosttls.Config) *Transport {
	if config == nil {
		config = &gosttls.Config{
			ClientSessionCache: gosttls.NewLRUClientSessionCache(128),
		}
	} else {
		config = config.Clone()
	}

	proxyConfig := &gosttls.Config{
		ClientSessionCache: gosttls.NewLRUClientSessionCache(128),
	}
	netDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	return &Transport{
		Proxy:                    ProxyFromEnvironment,
		DialContext:              netDialer.DialContext,
		TLSClientConfig:          config,
		ProxyTLSClientConfig:     proxyConfig,
		TLSHandshakeTimeout:      10 * time.Second,
		ProxyTLSHandshakeTimeout: 10 * time.Second,
		ProxyConnectTimeout:      time.Minute,
		MaxIdleConns:             100,
		IdleConnTimeout:          90 * time.Second,
		ExpectContinueTimeout:    time.Second,
		Protocols:                protocols,
	}
}

// NewHTTP1Transport returns a transport restricted to HTTP/1.1.
func NewHTTP1Transport(config *gosttls.Config) *Transport {
	t := NewTransport(config)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	t.Protocols = protocols
	return t
}

// NewClient returns an HTTP client backed by NewTransport.
func NewClient(config *gosttls.Config) *http.Client {
	return &http.Client{Transport: NewTransport(config)}
}
