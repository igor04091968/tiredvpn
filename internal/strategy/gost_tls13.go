package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/log"
	"github.com/tiredvpn/tiredvpn/internal/protect"
	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/xtaci/smux"
	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	gostx509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

const GosuslugiSNI = "www.gosuslugi.ru"
const GOSTTLS13StrategyID = "gost_tls13_gosuslugi"

// GOSTTLS13Strategy is an opt-in RFC 9367 TLS 1.3 transport. The endpoint is
// still the configured TiredVPN server; GosuslugiSNI is only sent as SNI.
type GOSTTLS13Strategy struct {
	manager *Manager
	pins    [][sha256.Size]byte
	port    int
}

func NewGOSTTLS13Strategy(manager *Manager, pinHex string, port int) (*GOSTTLS13Strategy, error) {
	var s GOSTTLS13Strategy
	if manager == nil {
		return nil, fmt.Errorf("gost_tls13: manager is required")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("gost_tls13: listener port must be explicitly set to 1..65535")
	}
	parts := strings.Split(pinHex, ",")
	if len(parts) > 2 {
		return nil, fmt.Errorf("gost_tls13: configure one or two certificate pins")
	}
	for _, part := range parts {
		decoded, err := hex.DecodeString(strings.TrimSpace(part))
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("gost_tls13: each certificate pin must be 64 hexadecimal SHA-256 characters")
		}
		var pin [sha256.Size]byte
		copy(pin[:], decoded)
		if len(s.pins) == 1 && s.pins[0] == pin {
			return nil, fmt.Errorf("gost_tls13: certificate pins must be distinct")
		}
		s.pins = append(s.pins, pin)
	}

	s.manager = manager
	s.port = port
	return &s, nil
}

func (s *GOSTTLS13Strategy) Name() string         { return "GOST TLS 1.3 (Gosuslugi SNI)" }
func (s *GOSTTLS13Strategy) ID() string           { return GOSTTLS13StrategyID }
func (s *GOSTTLS13Strategy) Priority() int        { return 70 }
func (s *GOSTTLS13Strategy) RequiresServer() bool { return true }
func (s *GOSTTLS13Strategy) Description() string {
	return "Experimental strict GOST TLS 1.3 (RFC 9367), SNI www.gosuslugi.ru; requires server GOST certificate and pinned SHA-256 certificate fingerprint."
}

func (s *GOSTTLS13Strategy) Probe(ctx context.Context, target string) error {
	addr, err := s.serverAddr(ctx)
	if err != nil {
		return err
	}
	d := gostProtectedDialer(3 * time.Second)
	c, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = c.Close()
	}
	return err
}

func (s *GOSTTLS13Strategy) Connect(ctx context.Context, target string) (net.Conn, error) {
	addr, err := s.serverAddr(ctx)
	if err != nil {
		return nil, err
	}
	log.Info("GOST TLS: dialing TCP %s (SNI=%s)", addr, GosuslugiSNI)
	d := gostProtectedDialer(15 * time.Second)
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Debug("GOST TLS: TCP dial failed for %s: %v", addr, err)
		return nil, fmt.Errorf("gost_tls13: TCP dial: %w", err)
	}
	log.Info("GOST TLS: TCP connected to %s; starting TLS handshake", addr)
	return s.handshakeMux(ctx, raw)
}

// Protect before connect: after the TUN is active, even the TCP SYN must bypass
// the VPN. Linux without an Android protector and other platforms are no-ops.
func gostProtectedDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var protectErr error
			if err := raw.Control(func(fd uintptr) {
				protectErr = protect.ProtectRawFd(int(fd))
			}); err != nil {
				return err
			}
			return protectErr
		},
	}
}

func (s *GOSTTLS13Strategy) serverAddr(ctx context.Context) (string, error) {
	endpoint := s.manager.GetServerAddr(ctx)
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("gost_tls13: invalid server endpoint %q: %w", endpoint, err)
	}
	return net.JoinHostPort(host, strconv.Itoa(s.port)), nil
}

// handshakeMux is kept separate so pin verification can use the GOST library's
// raw certificate callback (its verified-chain type differs from crypto/x509).
func (s *GOSTTLS13Strategy) handshakeMux(ctx context.Context, raw net.Conn) (net.Conn, error) {
	config := gosttls.GOSTConfig(&gosttls.Config{
		ServerName:            GosuslugiSNI,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: s.verifyPeerCertificate,
	})
	config.CryptoProClientHello = true
	tlsConn := gosttls.Client(raw, config)
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	} else {
		_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Debug("GOST TLS: handshake failed: %v", err)
		_ = raw.Close()
		return nil, fmt.Errorf("gost_tls13: TLS handshake: %w", err)
	}
	if tlsConn.ConnectionState().Version != gosttls.VersionTLS13 || !isGOSTSuite(tlsConn.ConnectionState().CipherSuite) {
		_ = raw.Close()
		return nil, fmt.Errorf("gost_tls13: peer did not negotiate a GOST TLS 1.3 cipher suite")
	}
	log.Info("GOST TLS: TLS 1.3 negotiated (suite=0x%04x), certificate pin verified", tlsConn.ConnectionState().CipherSuite)
	if err := protocol.WriteDispatch(tlsConn, protocol.TypeMux); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("gost_tls13: mux dispatch: %w", err)
	}
	sess, err := smux.Client(tlsConn, smux.DefaultConfig())
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("gost_tls13: smux: %w", err)
	}
	stream, err := sess.OpenStream()
	if err != nil {
		_ = sess.Close()
		_ = raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return &gostTLSMuxConn{Conn: stream, sess: sess, raw: raw}, nil
}

// Trust only the explicitly configured leaf DER hashes. Renewal with the same
// public key still requires a new pin; no certificate is learned from the peer.
func (s *GOSTTLS13Strategy) verifyPeerCertificate(rawCerts [][]byte, _ [][]*gostx509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("gost_tls13: server sent no certificate")
	}
	got := sha256.Sum256(rawCerts[0])
	matched := false
	for _, pin := range s.pins {
		if got == pin {
			matched = true
		}
	}
	if !matched {
		return fmt.Errorf("gost_tls13: server certificate pin mismatch")
	}
	leaf, err := gostx509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("gost_tls13: parse pinned server certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("gost_tls13: pinned server certificate is outside its validity period")
	}
	return nil
}

type gostTLSMuxConn struct {
	net.Conn
	sess *smux.Session
	raw  net.Conn
}

func (c *gostTLSMuxConn) Close() error {
	e1 := c.Conn.Close()
	e2 := c.sess.Close()
	e3 := c.raw.Close()
	if e1 != nil {
		return e1
	}
	if e2 != nil {
		return e2
	}
	return e3
}

func isGOSTSuite(id uint16) bool { return id >= 0xC103 && id <= 0xC106 }

var _ io.ReadWriteCloser = (*gostTLSMuxConn)(nil)
