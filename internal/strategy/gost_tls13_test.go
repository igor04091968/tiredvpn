package strategy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/protocol"
	"github.com/xtaci/smux"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"gitverse.ru/uzer_007/gogost/v3/gosttls"
	gostx509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func TestNewGOSTTLS13StrategyRequiresExactCertificatePin(t *testing.T) {
	manager := NewManager()
	if _, err := NewGOSTTLS13Strategy(manager, strings.Repeat("a", 64), 0); err == nil {
		t.Fatal("missing dedicated server port was accepted")
	}
	for _, bad := range []string{"", "abcd", strings.Repeat("z", 64), strings.Repeat("a", 62), strings.Repeat("a", 64) + ",", "," + strings.Repeat("a", 64), strings.Repeat("a", 64) + "," + strings.Repeat("a", 64), strings.Repeat("a", 64) + "," + strings.Repeat("b", 64) + "," + strings.Repeat("c", 64)} {
		if _, err := NewGOSTTLS13Strategy(manager, bad, 12444); err == nil {
			t.Fatalf("pin %q unexpectedly accepted", bad)
		}
	}
	s, err := NewGOSTTLS13Strategy(manager, strings.Repeat("a", 64), 12444)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID() != "gost_tls13_gosuslugi" || !s.RequiresServer() {
		t.Fatalf("unexpected strategy metadata: id=%q requiresServer=%v", s.ID(), s.RequiresServer())
	}
}

func TestGOSTTLSStrategyRequiresExplicitSelection(t *testing.T) {
	cfg := DefaultManagerConfig{ServerAddr: "127.0.0.1:443", Secret: []byte("test"), GOSTTLSPin: strings.Repeat("a", 64), GOSTTLSPort: 12444}
	if ids := NewDefaultManager(cfg).ListStrategyIDs(); strings.Contains(ids, GOSTTLS13StrategyID) {
		t.Fatalf("GOST candidate registered without explicit enable: %s", ids)
	}
	cfg.GOSTTLSEnabled = true
	if ids := NewDefaultManager(cfg).ListStrategyIDs(); !strings.Contains(ids, GOSTTLS13StrategyID) {
		t.Fatalf("explicitly enabled GOST candidate missing: %s", ids)
	}
}

func TestGOSTTLS13PinAndMuxRoundTrip(t *testing.T) {
	priv, err := gost3410.GenPrivateKey(gost3410.CurveIdtc26gost341012256paramSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tpl := &gostx509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: GosuslugiSNI}, DNSNames: []string{GosuslugiSNI}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: gostx509.KeyUsageDigitalSignature | gostx509.KeyUsageCertSign, ExtKeyUsage: []gostx509.ExtKeyUsage{gostx509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := gostx509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	// Construct the TLS certificate from DER and PKCS #8 using the library's
	// public parsers, matching its documented deployment format.
	keyDER, err := gostx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := gosttls.X509KeyPair(pemEncode("CERTIFICATE", der), pemEncode("PRIVATE KEY", keyDER))
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(der)
	for name, pinList := range map[string]string{
		"single": hex.EncodeToString(pin[:]),
		"first":  hex.EncodeToString(pin[:]) + "," + strings.Repeat("0", 64),
		"second": strings.Repeat("0", 64) + "," + hex.EncodeToString(pin[:]),
	} {
		t.Run(name, func(t *testing.T) {
			strategy, err := NewGOSTTLS13Strategy(NewManager(), pinList, 12444)
			if err != nil {
				t.Fatal(err)
			}
			client, server := net.Pipe()
			defer client.Close()
			go func() {
				defer server.Close()
				sc := gosttls.Server(server, gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{cert}}))
				if sc.Handshake() != nil {
					return
				}
				if kind, e := protocol.ReadDispatch(sc); e != nil || kind != protocol.TypeMux {
					return
				}
				sess, e := smux.Server(sc, smux.DefaultConfig())
				if e != nil {
					return
				}
				defer sess.Close()
				stream, e := sess.AcceptStream()
				if e != nil {
					return
				}
				_, _ = io.Copy(stream, stream)
			}()
			_ = client.SetDeadline(time.Now().Add(15 * time.Second))
			stream, err := strategy.handshakeMux(context.Background(), client)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := stream.Write([]byte("round-trip")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len("round-trip"))
			if _, err := io.ReadFull(stream, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != "round-trip" {
				t.Fatalf("echo = %q", got)
			}
		})
	}

	badPinStrategy, err := NewGOSTTLS13Strategy(NewManager(), strings.Repeat("0", 64), 12444)
	if err != nil {
		t.Fatal(err)
	}
	client2, server2 := net.Pipe()
	defer client2.Close()
	go func() {
		defer server2.Close()
		_ = gosttls.Server(server2, gosttls.GOSTConfig(&gosttls.Config{Certificates: []gosttls.Certificate{cert}})).Handshake()
	}()
	_ = client2.SetDeadline(time.Now().Add(15 * time.Second))
	if badConn, err := badPinStrategy.handshakeMux(context.Background(), client2); err == nil {
		_ = badConn.Close()
		t.Fatal("connection with wrong server certificate pin succeeded")
	}
}

func pemEncode(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func TestGOSTCertificatePinRotation(t *testing.T) {
	priv, err := gost3410.GenPrivateKey(gost3410.CurveIdtc26gost341012256paramSetA(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	makeCert := func(serial int64, before, after time.Time) []byte {
		t.Helper()
		tpl := &gostx509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "rotation"}, NotBefore: before, NotAfter: after, KeyUsage: gostx509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: true}
		der, err := gostx509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	old := makeCert(1, now.Add(-time.Hour), now.Add(time.Hour))
	newCert := makeCert(2, now.Add(-time.Hour), now.Add(2*time.Hour))
	unknown := makeCert(3, now.Add(-time.Hour), now.Add(2*time.Hour))
	expired := makeCert(4, now.Add(-2*time.Hour), now.Add(-time.Hour))
	future := makeCert(5, now.Add(time.Hour), now.Add(2*time.Hour))
	pin := func(der []byte) string { sum := sha256.Sum256(der); return hex.EncodeToString(sum[:]) }
	for _, tc := range []struct {
		name, pins string
		der        []byte
		wantErr    bool
	}{
		{"old during overlap", pin(old) + "," + pin(newCert), old, false},
		{"renewed same key during overlap", pin(old) + "," + pin(newCert), newCert, false},
		{"unlisted same key", pin(old) + "," + pin(newCert), unknown, true},
		{"renewal needs new pin", pin(old), newCert, true},
		{"old removed", pin(newCert), old, true},
		{"new after overlap", pin(newCert), newCert, false},
		{"expired pinned", pin(old) + "," + pin(expired), expired, true},
		{"future pinned", pin(old) + "," + pin(future), future, true},
		{"empty chain", pin(old) + "," + pin(newCert), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewGOSTTLS13Strategy(NewManager(), tc.pins, 12444)
			if err != nil {
				t.Fatal(err)
			}
			var chain [][]byte
			if tc.der != nil {
				chain = [][]byte{tc.der}
			}
			err = s.verifyPeerCertificate(chain, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("verification error = %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
	// Invalid DER is refused even when its exact hash was configured.
	badDER := []byte("invalid certificate")
	s2, err := NewGOSTTLS13Strategy(NewManager(), pin(badDER), 12444)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.verifyPeerCertificate([][]byte{badDER}, nil); err == nil {
		t.Fatal("pinned malformed certificate accepted")
	}
}
