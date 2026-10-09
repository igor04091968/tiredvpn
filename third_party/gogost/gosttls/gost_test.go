package gosttls

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func testGOSTCertificate(t testing.TB, name string, curve *gost3410.Curve) (Certificate, *x509.Certificate) {
	t.Helper()

	private, err := gost3410.GenPrivateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := private.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return pair, parsed
}

func TestGOSTTLS13CipherSuites(t *testing.T) {
	certificate, leaf := testGOSTCertificate(t, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	for _, suite := range GOSTCipherSuiteIDs() {
		suite := suite
		t.Run(CipherSuiteName(suite), func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			deadline := time.Now().Add(10 * time.Second)
			_ = clientSide.SetDeadline(deadline)
			_ = serverSide.SetDeadline(deadline)

			serverConfig := GOSTConfig(&Config{
				Certificates: []Certificate{certificate},
			})
			serverConfig.CipherSuitesTLS13 = []uint16{suite}
			serverConfig.CurvePreferences = []CurveID{GOSTCurve256A}
			clientConfig := GOSTConfig(&Config{
				RootCAs:    roots,
				ServerName: "server.test",
			})
			clientConfig.CipherSuitesTLS13 = []uint16{suite}
			clientConfig.CurvePreferences = []CurveID{GOSTCurve256A}

			server := Server(serverSide, serverConfig)
			client := Client(clientSide, clientConfig)
			serverErr := make(chan error, 1)
			go func() { serverErr <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("server handshake: %v", err)
			}
			if state := client.ConnectionState(); state.Version != VersionTLS13 || state.CipherSuite != suite {
				t.Fatalf("unexpected client state: version=%x suite=%x", state.Version, state.CipherSuite)
			}

			payload := bytes.Repeat([]byte("gost-tls-record-"), 1024)
			writeErr := make(chan error, 1)
			go func() {
				_, err := client.Write(payload)
				writeErr <- err
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(server, got); err != nil {
				t.Fatalf("read application data: %v", err)
			}
			if err := <-writeErr; err != nil {
				t.Fatalf("write application data: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("application data mismatch")
			}
		})
	}
}

func TestGOSTKeyShareAllGroups(t *testing.T) {
	for _, group := range GOSTCurveIDs() {
		left, err := generateTLS13KeyShare(rand.Reader, group)
		if err != nil {
			t.Fatalf("%s: generate left key: %v", group, err)
		}
		right, err := generateTLS13KeyShare(rand.Reader, group)
		if err != nil {
			t.Fatalf("%s: generate right key: %v", group, err)
		}
		leftSecret, err := left.ECDH(right.PublicKeyBytes())
		if err != nil {
			t.Fatalf("%s: left ECDH: %v", group, err)
		}
		rightSecret, err := right.ECDH(left.PublicKeyBytes())
		if err != nil {
			t.Fatalf("%s: right ECDH: %v", group, err)
		}
		if !bytes.Equal(leftSecret, rightSecret) {
			t.Fatalf("%s: shared secrets differ", group)
		}
	}
}

func TestGOSTConfigUsesStrictRFC9367Profile(t *testing.T) {
	config := GOSTConfig(&Config{ServerName: "server.test"})
	if config.MinVersion != VersionTLS13 || config.MaxVersion != VersionTLS13 {
		t.Fatalf("version range = %x..%x", config.MinVersion, config.MaxVersion)
	}
	if !reflect.DeepEqual(config.CipherSuitesTLS13, GOSTCipherSuiteIDs()) {
		t.Fatalf("cipher suites = %x", config.CipherSuitesTLS13)
	}
	if !reflect.DeepEqual(config.CurvePreferences, GOSTCurveIDs()) {
		t.Fatalf("groups = %v", config.CurvePreferences)
	}
	if !reflect.DeepEqual(config.SignatureSchemes, GOSTSignatureSchemes()) {
		t.Fatalf("signature schemes = %x", config.SignatureSchemes)
	}

	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	hello, _, _, err := Client(clientSide, config).makeClientHello()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hello.cipherSuites, GOSTCipherSuiteIDs()) {
		t.Fatalf("ClientHello cipher suites = %x", hello.cipherSuites)
	}
	if !reflect.DeepEqual(hello.supportedCurves, GOSTCurveIDs()) {
		t.Fatalf("ClientHello groups = %v", hello.supportedCurves)
	}
	if !reflect.DeepEqual(hello.supportedSignatureAlgorithms, GOSTSignatureSchemes()) {
		t.Fatalf("ClientHello signature schemes = %x", hello.supportedSignatureAlgorithms)
	}
}

func TestMixedDefaultClientHelloCarriesGOSTAndStandardKeyShares(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	hello, _, _, err := Client(clientSide, &Config{ServerName: "server.test"}).makeClientHello()
	if err != nil {
		t.Fatal(err)
	}
	if len(hello.keyShares) < 2 {
		t.Fatalf("default ClientHello has %d key shares, want GOST and standard fallback", len(hello.keyShares))
	}
	if !isGOSTCurve(hello.keyShares[0].group) {
		t.Fatalf("first key share is %v, want a GOST group", hello.keyShares[0].group)
	}
	hasStandard := false
	for _, share := range hello.keyShares[1:] {
		if !isGOSTCurve(share.group) {
			hasStandard = true
			break
		}
	}
	if !hasStandard {
		t.Fatalf("default key shares %v have no standard/PQ fallback", hello.keyShares)
	}
}

func TestTLS13RejectsCipherSuiteGroupProfileMismatch(t *testing.T) {
	certificate, leaf := testGOSTCertificate(t, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	for _, test := range []struct {
		name  string
		suite uint16
		group CurveID
	}{
		{"gost-suite-standard-group", TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L, X25519},
		{"standard-suite-gost-group", TLS_AES_128_GCM_SHA256, GOSTCurve256A},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverConfig := &Config{
				Certificates:           []Certificate{certificate},
				MinVersion:             VersionTLS13,
				MaxVersion:             VersionTLS13,
				CipherSuitesTLS13:      []uint16{test.suite},
				CurvePreferences:       []CurveID{test.group},
				SessionTicketsDisabled: true,
			}
			clientConfig := serverConfig.Clone()
			clientConfig.Certificates = nil
			clientConfig.RootCAs = roots
			clientConfig.ServerName = "server.test"

			_, _, clientErr, serverErr := sessionConnection(clientConfig, serverConfig)
			if clientErr == nil && serverErr == nil {
				t.Fatal("incompatible TLS 1.3 cipher suite and group were accepted")
			}
		})
	}
}

func handshakePair(t *testing.T, clientConfig, serverConfig *Config) (ConnectionState, ConnectionState) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	deadline := time.Now().Add(10 * time.Second)
	_ = clientSide.SetDeadline(deadline)
	_ = serverSide.SetDeadline(deadline)

	server := Server(serverSide, serverConfig)
	client := Client(clientSide, clientConfig)
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return client.ConnectionState(), server.ConnectionState()
}

func TestGOSTTLS13SignatureSchemes(t *testing.T) {
	curves := []*gost3410.Curve{
		gost3410.CurveIdtc26gost341012256paramSetA(),
		gost3410.CurveIdtc26gost341012256paramSetB(),
		gost3410.CurveIdtc26gost341012256paramSetC(),
		gost3410.CurveIdtc26gost341012256paramSetD(),
		gost3410.CurveIdtc26gost341012512paramSetA(),
		gost3410.CurveIdtc26gost341012512paramSetB(),
		gost3410.CurveIdtc26gost341012512paramSetC(),
	}
	for _, curve := range curves {
		curve := curve
		t.Run(curve.Name, func(t *testing.T) {
			certificate, leaf := testGOSTCertificate(t, "server.test", curve)
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			serverConfig := GOSTConfig(&Config{Certificates: []Certificate{certificate}})
			clientConfig := GOSTConfig(&Config{RootCAs: roots, ServerName: "server.test"})
			serverConfig.CipherSuitesTLS13 = []uint16{TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L}
			clientConfig.CipherSuitesTLS13 = []uint16{TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L}
			serverConfig.CurvePreferences = []CurveID{GOSTCurve256A}
			clientConfig.CurvePreferences = []CurveID{GOSTCurve256A}
			handshakePair(t, clientConfig, serverConfig)
		})
	}
}

func TestGOSTTLS13MutualAuthentication(t *testing.T) {
	serverCertificate, serverLeaf := testGOSTCertificate(t, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	clientCertificate, clientLeaf := testGOSTCertificate(t, "client.test", gost3410.CurveIdtc26gost341012512paramSetC())
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverLeaf)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(clientLeaf)

	serverConfig := GOSTConfig(&Config{
		Certificates: []Certificate{serverCertificate},
		ClientAuth:   RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	})
	clientConfig := GOSTConfig(&Config{
		Certificates: []Certificate{clientCertificate},
		RootCAs:      serverRoots,
		ServerName:   "server.test",
	})
	clientState, serverState := handshakePair(t, clientConfig, serverConfig)
	if len(clientState.VerifiedChains) != 1 || len(serverState.VerifiedChains) != 1 {
		t.Fatalf("mutual verification missing: client=%d server=%d", len(clientState.VerifiedChains), len(serverState.VerifiedChains))
	}
}

func TestGOSTTLS13SessionResumption(t *testing.T) {
	certificate, leaf := testGOSTCertificate(t, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	serverConfig := GOSTConfig(&Config{Certificates: []Certificate{certificate}})
	clientConfig := GOSTConfig(&Config{
		RootCAs:            roots,
		ServerName:         "server.test",
		ClientSessionCache: NewLRUClientSessionCache(4),
	})

	connect := func() (ConnectionState, ConnectionState) {
		clientSide, serverSide := net.Pipe()
		deadline := time.Now().Add(10 * time.Second)
		_ = clientSide.SetDeadline(deadline)
		_ = serverSide.SetDeadline(deadline)
		server := Server(serverSide, serverConfig)
		serverErr := make(chan error, 1)
		go func() {
			defer serverSide.Close()
			if err := server.Handshake(); err != nil {
				serverErr <- err
				return
			}
			_, err := server.Write([]byte{1})
			serverErr <- err
		}()
		client := Client(clientSide, clientConfig)
		defer clientSide.Close()
		if err := client.Handshake(); err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		var applicationData [1]byte
		if _, err := io.ReadFull(client, applicationData[:]); err != nil {
			t.Fatalf("read after handshake: %v", err)
		}
		if err := <-serverErr; err != nil {
			t.Fatalf("server: %v", err)
		}
		return client.ConnectionState(), server.ConnectionState()
	}

	firstClient, firstServer := connect()
	if firstClient.DidResume || firstServer.DidResume {
		t.Fatal("first connection unexpectedly resumed")
	}
	if firstClient.LocalCertificate != nil {
		t.Fatalf("client LocalCertificate without client authentication = %x", firstClient.LocalCertificate)
	}
	if !reflect.DeepEqual(firstServer.LocalCertificate, certificate.Certificate) {
		t.Fatalf("server LocalCertificate = %x, want %x", firstServer.LocalCertificate, certificate.Certificate)
	}

	secondClient, secondServer := connect()
	if !secondClient.DidResume || !secondServer.DidResume {
		t.Fatal("second connection did not resume")
	}
	if secondClient.LocalCertificate != nil || secondServer.LocalCertificate != nil {
		t.Fatalf("resumed LocalCertificate: client=%x server=%x", secondClient.LocalCertificate, secondServer.LocalCertificate)
	}
}

func sessionConnection(clientConfig, serverConfig *Config) (clientState, serverState ConnectionState, clientErr, serverErr error) {
	clientSide, serverSide := net.Pipe()
	deadline := time.Now().Add(10 * time.Second)
	_ = clientSide.SetDeadline(deadline)
	_ = serverSide.SetDeadline(deadline)

	server := Server(serverSide, serverConfig)
	serverResult := make(chan error, 1)
	go func() {
		err := server.Handshake()
		if err == nil {
			// A read after the handshake lets the client process the TLS 1.3
			// NewSessionTicket before the connection is closed.
			_, err = server.Write([]byte{1})
		}
		serverResult <- err
	}()

	client := Client(clientSide, clientConfig)
	clientErr = client.Handshake()
	if clientErr == nil {
		var applicationData [1]byte
		_, clientErr = io.ReadFull(client, applicationData[:])
	}
	clientState = client.ConnectionState()
	_ = clientSide.Close()
	serverErr = <-serverResult
	serverState = server.ConnectionState()
	_ = serverSide.Close()
	return
}

func TestSessionResumptionRevalidatesRootCAs(t *testing.T) {
	certificate, leaf := testGOSTCertificate(t, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	serverConfig := GOSTConfig(&Config{Certificates: []Certificate{certificate}})
	cache := NewLRUClientSessionCache(4)
	clientConfig := GOSTConfig(&Config{
		RootCAs:            roots,
		ServerName:         "server.test",
		ClientSessionCache: cache,
	})

	firstClient, _, clientErr, serverErr := sessionConnection(clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("initial connection: client=%v server=%v", clientErr, serverErr)
	}
	if firstClient.DidResume {
		t.Fatal("initial connection unexpectedly resumed")
	}

	untrustedClient := clientConfig.Clone()
	untrustedClient.RootCAs = x509.NewCertPool()
	secondClient, _, clientErr, _ := sessionConnection(untrustedClient, serverConfig)
	if clientErr == nil {
		t.Fatal("connection resumed or verified after the configured server roots were removed")
	}
	if secondClient.DidResume {
		t.Fatal("connection resumed with a certificate chain no longer trusted by RootCAs")
	}
}

func TestSessionResumptionRevalidatesClientCAs(t *testing.T) {
	serverCertificate, serverLeaf := testGOSTCertificate(t, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	clientCertificate, clientLeaf := testGOSTCertificate(t, "client.test", gost3410.CurveIdtc26gost341012512paramSetC())
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverLeaf)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(clientLeaf)

	serverConfig := GOSTConfig(&Config{
		Certificates: []Certificate{serverCertificate},
		ClientAuth:   RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	})
	// Keep ticket encryption stable across the two server configurations.
	for i := range serverConfig.SessionTicketKey {
		serverConfig.SessionTicketKey[i] = byte(i + 1)
	}
	clientConfig := GOSTConfig(&Config{
		Certificates:       []Certificate{clientCertificate},
		RootCAs:            serverRoots,
		ServerName:         "server.test",
		ClientSessionCache: NewLRUClientSessionCache(4),
	})

	_, _, clientErr, serverErr := sessionConnection(clientConfig, serverConfig)
	if clientErr != nil || serverErr != nil {
		t.Fatalf("initial mutual-auth connection: client=%v server=%v", clientErr, serverErr)
	}

	untrustedServer := serverConfig.Clone()
	untrustedServer.ClientCAs = x509.NewCertPool()
	secondClient, secondServer, clientErr, serverErr := sessionConnection(clientConfig, untrustedServer)
	if clientErr == nil && serverErr == nil {
		t.Fatal("connection resumed or verified after the configured client roots were removed")
	}
	if secondClient.DidResume || secondServer.DidResume {
		t.Fatal("connection resumed with a certificate chain no longer trusted by ClientCAs")
	}
}

func TestMultipleKeyUpdatesInOneRecordAreRejected(t *testing.T) {
	certificate, leaf := testGOSTCertificate(t, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	for _, requestUpdate := range []bool{false, true} {
		t.Run(fmt.Sprintf("requestUpdate=%t", requestUpdate), func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			deadline := time.Now().Add(10 * time.Second)
			_ = clientSide.SetDeadline(deadline)
			_ = serverSide.SetDeadline(deadline)

			server := Server(serverSide, GOSTConfig(&Config{Certificates: []Certificate{certificate}}))
			client := Client(clientSide, GOSTConfig(&Config{RootCAs: roots, ServerName: "server.test"}))
			serverHandshake := make(chan error, 1)
			go func() { serverHandshake <- server.Handshake() }()
			if err := client.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if err := <-serverHandshake; err != nil {
				t.Fatalf("server handshake: %v", err)
			}

			serverRead := make(chan error, 1)
			clientRead := make(chan error, 1)
			go func() {
				var b [1]byte
				_, err := server.Read(b[:])
				serverRead <- err
			}()
			go func() {
				var b [1]byte
				_, err := client.Read(b[:])
				clientRead <- err
			}()

			message, err := (&keyUpdateMsg{updateRequested: requestUpdate}).marshal()
			if err != nil {
				t.Fatal(err)
			}
			client.out.Lock()
			_, writeErr := client.writeRecordLocked(recordTypeHandshake, append(message, message...))
			client.out.Unlock()
			if writeErr != nil {
				t.Fatalf("write key updates: %v", writeErr)
			}

			if err := <-serverRead; err == nil || !strings.Contains(err.Error(), "handshake buffer not empty") {
				t.Fatalf("server accepted multiple key updates in one record: %v", err)
			}
			if err := <-clientRead; err == nil {
				t.Fatal("client did not receive an alert for multiple key updates")
			}
		})
	}
}
