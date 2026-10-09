package gosthttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
)

var http2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// Serve accepts GOST TLS connections and automatically serves HTTP/1.1 or
// HTTP/2 according to ALPN. The external connection is always encrypted;
// UnencryptedHTTP2 is used only as the internal net/http bridge.
func Serve(server *http.Server, listener net.Listener, config *gosttls.Config) error {
	return serve(server, listener, config, false)
}

// ServeHTTP1 serves GOST TLS connections restricted to HTTP/1.1.
func ServeHTTP1(server *http.Server, listener net.Listener, config *gosttls.Config) error {
	return serve(server, listener, config, true)
}

func serve(server *http.Server, listener net.Listener, config *gosttls.Config, forceHTTP1 bool) error {
	if server == nil {
		return errors.New("gosthttp: nil *http.Server")
	}
	if listener == nil {
		return errors.New("gosthttp: nil net.Listener")
	}
	if config == nil {
		return errors.New("gosthttp: nil TLS config")
	}
	if len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil {
		return errors.New("gosthttp: TLS config has no certificate source")
	}

	http1, http2 := serverProtocols(server, forceHTTP1)
	if !http1 && !http2 {
		return errors.New("gosthttp: neither HTTP/1.1 nor HTTP/2 is enabled")
	}
	tlsConfig := config.Clone()
	tlsConfig.NextProtos = nil
	if http2 {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "h2")
	}
	if http1 {
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
	}
	// Configs returned dynamically must obey the same wire protocol policy as
	// http.Server.Protocols. Clone them so the caller's Config is not mutated.
	if getConfig := tlsConfig.GetConfigForClient; getConfig != nil {
		wireNextProtos := append([]string(nil), tlsConfig.NextProtos...)
		tlsConfig.GetConfigForClient = func(info *gosttls.ClientHelloInfo) (*gosttls.Config, error) {
			selected, err := getConfig(info)
			if err != nil || selected == nil {
				return selected, err
			}
			selected = selected.Clone()
			selected.NextProtos = append([]string(nil), wireNextProtos...)
			return selected, nil
		}
	}

	internalProtocols := new(http.Protocols)
	internalProtocols.SetHTTP1(http1)
	internalProtocols.SetUnencryptedHTTP2(http2)
	server.Protocols = internalProtocols

	previousConnContext := server.ConnContext
	server.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		if previousConnContext != nil {
			ctx = previousConnContext(ctx, conn)
			if ctx == nil {
				panic("gosthttp: http.Server.ConnContext returned nil")
			}
		}
		return contextWithConnectionState(ctx, conn)
	}

	secureListener := &serverListener{
		Listener: listener,
		config:   tlsConfig,
		http1:    http1,
		http2:    http2,
		timeout:  serverTLSHandshakeTimeout(server),
		server:   server,
	}
	return server.Serve(secureListener)
}

func serverProtocols(server *http.Server, forceHTTP1 bool) (http1, http2 bool) {
	if forceHTTP1 {
		return true, false
	}
	if server.Protocols == nil {
		return true, true
	}
	return server.Protocols.HTTP1(), server.Protocols.HTTP2()
}

func serverTLSHandshakeTimeout(server *http.Server) time.Duration {
	var result time.Duration
	for _, timeout := range [...]time.Duration{
		server.ReadHeaderTimeout,
		server.ReadTimeout,
		server.WriteTimeout,
	} {
		if timeout > 0 && (result == 0 || timeout < result) {
			result = timeout
		}
	}
	return result
}

type serverListener struct {
	net.Listener
	config  *gosttls.Config
	http1   bool
	http2   bool
	timeout time.Duration
	server  *http.Server
}

func (listener *serverListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, err
	}
	secure := gosttls.Server(conn, listener.config)
	return &serverConn{
		Conn:    secure,
		secure:  secure,
		http1:   listener.http1,
		http2:   listener.http2,
		timeout: listener.timeout,
		server:  listener.server,
	}, nil
}

type serverConn struct {
	net.Conn
	secure  *gosttls.Conn
	http1   bool
	http2   bool
	timeout time.Duration
	server  *http.Server

	once         sync.Once
	handshakeErr error
	reader       *bufio.Reader

	stateMu sync.RWMutex
	state   gosttls.ConnectionState
}

func (conn *serverConn) Read(buffer []byte) (int, error) {
	if err := conn.ensureHandshake(); err != nil {
		return 0, err
	}
	return conn.reader.Read(buffer)
}

func (conn *serverConn) Write(buffer []byte) (int, error) {
	if err := conn.ensureHandshake(); err != nil {
		return 0, err
	}
	return conn.secure.Write(buffer)
}

// GOSTConnectionState deliberately has a distinct name from crypto/tls.Conn's
// ConnectionState. This keeps Request.TLS nil while exposing the complete
// gostx509-backed state through ConnectionState(request).
func (conn *serverConn) GOSTConnectionState() gosttls.ConnectionState {
	conn.stateMu.RLock()
	defer conn.stateMu.RUnlock()
	return conn.state
}

func (conn *serverConn) ensureHandshake() error {
	conn.once.Do(func() {
		start := time.Now()
		ctx := context.Background()
		var cancel context.CancelFunc
		if conn.timeout > 0 {
			ctx, cancel = context.WithTimeout(ctx, conn.timeout)
			defer cancel()
			_ = conn.secure.SetDeadline(start.Add(conn.timeout))
		}

		if err := conn.secure.HandshakeContext(ctx); err != nil {
			conn.handshakeErr = err
			return
		}
		state := conn.secure.ConnectionState()
		conn.stateMu.Lock()
		conn.state = state
		conn.stateMu.Unlock()
		conn.reader = bufio.NewReader(conn.secure)

		switch state.NegotiatedProtocol {
		case "h2":
			if !conn.http2 {
				conn.handshakeErr = errors.New("gosthttp: peer selected disabled h2 protocol")
				return
			}
			preface, err := conn.reader.Peek(len(http2ClientPreface))
			if err != nil {
				conn.handshakeErr = fmt.Errorf("gosthttp: read HTTP/2 client preface: %w", err)
				return
			}
			if !bytes.Equal(preface, http2ClientPreface) {
				conn.handshakeErr = errors.New("gosthttp: ALPN selected h2 but the HTTP/2 client preface is missing")
				return
			}
		case "", "http/1.1":
			if !conn.http1 {
				conn.handshakeErr = errors.New("gosthttp: peer did not negotiate h2 and HTTP/1.1 is disabled")
				return
			}
			if readerStartsWith(conn.reader, http2ClientPreface) {
				conn.handshakeErr = errors.New("gosthttp: HTTP/2 client preface received without h2 ALPN")
				return
			}
		default:
			conn.handshakeErr = fmt.Errorf("gosthttp: unsupported negotiated ALPN protocol %q", state.NegotiatedProtocol)
			return
		}

		conn.restoreHTTPDeadlines(start)
	})
	return conn.handshakeErr
}

func readerStartsWith(reader *bufio.Reader, prefix []byte) bool {
	for index, expected := range prefix {
		buffer, err := reader.Peek(index + 1)
		if err != nil || buffer[index] != expected {
			return false
		}
	}
	return true
}

func (conn *serverConn) restoreHTTPDeadlines(start time.Time) {
	var readDeadline time.Time
	if conn.server.ReadHeaderTimeout > 0 {
		readDeadline = start.Add(conn.server.ReadHeaderTimeout)
	} else if conn.server.ReadTimeout > 0 {
		readDeadline = start.Add(conn.server.ReadTimeout)
	}
	var writeDeadline time.Time
	if conn.server.WriteTimeout > 0 {
		writeDeadline = start.Add(conn.server.WriteTimeout)
	}
	_ = conn.secure.SetReadDeadline(readDeadline)
	_ = conn.secure.SetWriteDeadline(writeDeadline)
}
