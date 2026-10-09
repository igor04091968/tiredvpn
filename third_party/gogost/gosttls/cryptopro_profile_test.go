package gosttls

import (
	"bytes"
	"context"
	"encoding/binary"
	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCryptoProClientHelloWire(t *testing.T) {
	var previous []byte
	for i := 0; i < 2; i++ {
		client, server := net.Pipe()
		cfg := GOSTConfig(&Config{ServerName: "www.gosuslugi.ru", InsecureSkipVerify: true})
		cfg.CryptoProClientHello = true
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		done := make(chan error, 1)
		go func() { done <- Client(client, cfg).HandshakeContext(ctx) }()
		header := make([]byte, 5)
		if _, err := io.ReadFull(server, header); err != nil {
			t.Fatal(err)
		}
		if header[0] != 22 || binary.BigEndian.Uint16(header[1:]) != VersionTLS12 {
			t.Fatalf("record=%x", header)
		}
		raw := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
		if _, err := io.ReadFull(server, raw); err != nil {
			t.Fatal(err)
		}
		server.Close()
		client.Close()
		cancel()
		<-done
		var h clientHelloMsg
		if !h.unmarshal(raw) {
			t.Fatal("invalid ClientHello")
		}
		if len(raw) != 357 {
			t.Fatalf("hello length=%d, want 357 (reference minus PHA and PSK-only mode)", len(raw))
		}
		if !reflect.DeepEqual(h.extensions, []uint16{65281, 35, 0, 23, 11, 10, 13, 43, 45, 51}) {
			t.Fatalf("extensions=%v", h.extensions)
		}
		if !reflect.DeepEqual(h.cipherSuites, []uint16{0xc104, 0xc103, 0xc106, 0xc105, 0x1301, 0x1302}) {
			t.Fatalf("suites=%x", h.cipherSuites)
		}
		if !reflect.DeepEqual(h.supportedCurves, []CurveID{34, 35, 36, 37, 38, 39, 40, 23, 24, 25, 29}) {
			t.Fatalf("groups=%v", h.supportedCurves)
		}
		if len(h.keyShares) != 2 || h.keyShares[0].group != 34 || len(h.keyShares[0].data) != 64 || h.keyShares[1].group != 23 || len(h.keyShares[1].data) != 65 {
			t.Fatalf("keyshares=%v", h.keyShares)
		}
		if h.serverName != "www.gosuslugi.ru" || len(h.alpnProtocols) != 0 || len(h.supportedSignatureAlgorithmsCert) != 0 || !reflect.DeepEqual(h.supportedVersions, []uint16{VersionTLS13}) {
			t.Fatal("wrong hello profile")
		}
		if previous != nil && bytes.Equal(previous, raw) {
			t.Fatal("reused random/session/key material")
		}
		previous = raw
	}
}

func TestCryptoProStrictNegotiationAndHRR(t *testing.T) {
	cert, _ := testGOSTCertificate(t, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	for _, tc := range []struct {
		name  string
		suite uint16
		curve CurveID
		ok    bool
	}{
		{"GOST", 0xc103, GOSTCurve256A, true},
		{"GOST-HRR", 0xc104, GOSTCurve256B, true},
		{"reject-AES", 0x1301, CurveP256, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			defer server.Close()
			deadline := time.Now().Add(4 * time.Second)
			client.SetDeadline(deadline)
			server.SetDeadline(deadline)
			cfg := GOSTConfig(&Config{ServerName: "server.test", InsecureSkipVerify: true})
			cfg.CryptoProClientHello = true
			scfg := &Config{MinVersion: VersionTLS13, MaxVersion: VersionTLS13, Certificates: []Certificate{cert}, CipherSuitesTLS13: []uint16{tc.suite}, CurvePreferences: []CurveID{tc.curve}}
			done := make(chan error, 1)
			go func() { done <- Server(server, scfg).Handshake() }()
			conn := Client(client, cfg)
			err = conn.Handshake()
			serverErr := <-done
			if tc.ok && (err != nil || serverErr != nil) {
				t.Fatalf("client=%v server=%v", err, serverErr)
			}
			if !tc.ok && (err == nil || !strings.Contains(err.Error(), "requires a GOST cipher")) {
				t.Fatalf("standard cipher not rejected at ServerHello: %v", err)
			}
		})
	}
}
