package gosttls

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	stdtls "crypto/tls"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

type go127Handshaker interface {
	Handshake() error
}

func completeGo127Handshake(t *testing.T, client, server go127Handshaker) {
	t.Helper()
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

func go127Pipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
	})
	deadline := time.Now().Add(10 * time.Second)
	if err := clientSide.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverSide.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return clientSide, serverSide
}

func mldsaInteropCertificate(t *testing.T) (Certificate, stdtls.Certificate, *x509.Certificate, *stdx509.Certificate) {
	t.Helper()
	private, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(301),
		Subject:               pkix.Name{CommonName: "mldsa.test"},
		DNSNames:              []string{"mldsa.test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.PublicKey(), private)
	if err != nil {
		t.Fatal(err)
	}
	standardLeaf, err := stdx509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	gostLeaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: gostLeaf},
		stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: standardLeaf},
		gostLeaf, standardLeaf
}

func TestGo127MLDSATLS13Interoperability(t *testing.T) {
	gostCertificate, standardCertificate, gostLeaf, standardLeaf := mldsaInteropCertificate(t)
	gostRoots := x509.NewCertPool()
	gostRoots.AddCert(gostLeaf)
	standardRoots := stdx509.NewCertPool()
	standardRoots.AddCert(standardLeaf)

	t.Run("gosttls-client", func(t *testing.T) {
		clientSide, serverSide := go127Pipe(t)
		client := Client(clientSide, &Config{
			RootCAs:          gostRoots,
			ServerName:       "mldsa.test",
			MinVersion:       VersionTLS13,
			MaxVersion:       VersionTLS13,
			CurvePreferences: []CurveID{X25519},
			SignatureSchemes: []SignatureScheme{MLDSA65},
		})
		server := stdtls.Server(serverSide, &stdtls.Config{
			Certificates:     []stdtls.Certificate{standardCertificate},
			MinVersion:       stdtls.VersionTLS13,
			MaxVersion:       stdtls.VersionTLS13,
			CurvePreferences: []stdtls.CurveID{stdtls.X25519},
		})
		completeGo127Handshake(t, client, server)
		if client.ConnectionState().PeerCertificates[0].PublicKeyAlgorithm != x509.MLDSA {
			t.Fatal("gosttls client did not parse the ML-DSA certificate")
		}
	})

	t.Run("gosttls-server", func(t *testing.T) {
		clientSide, serverSide := go127Pipe(t)
		client := stdtls.Client(clientSide, &stdtls.Config{
			RootCAs:          standardRoots,
			ServerName:       "mldsa.test",
			MinVersion:       stdtls.VersionTLS13,
			MaxVersion:       stdtls.VersionTLS13,
			CurvePreferences: []stdtls.CurveID{stdtls.X25519},
		})
		server := Server(serverSide, &Config{
			Certificates:     []Certificate{gostCertificate},
			MinVersion:       VersionTLS13,
			MaxVersion:       VersionTLS13,
			CurvePreferences: []CurveID{X25519},
			SignatureSchemes: []SignatureScheme{MLDSA65},
		})
		completeGo127Handshake(t, client, server)
		if client.ConnectionState().PeerCertificates[0].PublicKeyAlgorithm != stdx509.MLDSA {
			t.Fatal("crypto/tls client did not parse the ML-DSA certificate")
		}
	})
}

func TestGo127MLKEM1024TLS13Interoperability(t *testing.T) {
	gostCertificate, standardCertificate, gostLeaf, standardLeaf := standardInteropCertificate(t)
	gostRoots := x509.NewCertPool()
	gostRoots.AddCert(gostLeaf)
	standardRoots := stdx509.NewCertPool()
	standardRoots.AddCert(standardLeaf)

	t.Run("gosttls-client", func(t *testing.T) {
		clientSide, serverSide := go127Pipe(t)
		client := Client(clientSide, &Config{
			RootCAs:          gostRoots,
			ServerName:       "standard.test",
			MinVersion:       VersionTLS13,
			MaxVersion:       VersionTLS13,
			CurvePreferences: []CurveID{MLKEM1024},
		})
		server := stdtls.Server(serverSide, &stdtls.Config{
			Certificates:     []stdtls.Certificate{standardCertificate},
			MinVersion:       stdtls.VersionTLS13,
			MaxVersion:       stdtls.VersionTLS13,
			CurvePreferences: []stdtls.CurveID{stdtls.MLKEM1024},
		})
		completeGo127Handshake(t, client, server)
		if client.ConnectionState().CurveID != MLKEM1024 {
			t.Fatalf("gosttls client negotiated %v, want MLKEM1024", client.ConnectionState().CurveID)
		}
	})

	t.Run("gosttls-server", func(t *testing.T) {
		clientSide, serverSide := go127Pipe(t)
		client := stdtls.Client(clientSide, &stdtls.Config{
			RootCAs:          standardRoots,
			ServerName:       "standard.test",
			MinVersion:       stdtls.VersionTLS13,
			MaxVersion:       stdtls.VersionTLS13,
			CurvePreferences: []stdtls.CurveID{stdtls.MLKEM1024},
		})
		server := Server(serverSide, &Config{
			Certificates:     []Certificate{gostCertificate},
			MinVersion:       VersionTLS13,
			MaxVersion:       VersionTLS13,
			CurvePreferences: []CurveID{MLKEM1024},
		})
		completeGo127Handshake(t, client, server)
		if server.ConnectionState().CurveID != MLKEM1024 {
			t.Fatalf("gosttls server negotiated %v, want MLKEM1024", server.ConnectionState().CurveID)
		}
	})
}

func TestGo127LocalCertificate(t *testing.T) {
	certificate, _, leaf, _ := standardInteropCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	for _, version := range []uint16{VersionTLS12, VersionTLS13} {
		t.Run(VersionName(version), func(t *testing.T) {
			clientSide, serverSide := go127Pipe(t)
			client := Client(clientSide, &Config{
				Certificates: []Certificate{certificate},
				RootCAs:      roots,
				ServerName:   "standard.test",
				MinVersion:   version,
				MaxVersion:   version,
			})
			server := Server(serverSide, &Config{
				Certificates: []Certificate{certificate},
				ClientAuth:   RequestClientCert,
				MinVersion:   version,
				MaxVersion:   version,
			})
			completeGo127Handshake(t, client, server)
			if got := client.ConnectionState().LocalCertificate; !slices.EqualFunc(got, certificate.Certificate, bytes.Equal) {
				t.Fatalf("client LocalCertificate = %x, want %x", got, certificate.Certificate)
			}
			if got := server.ConnectionState().LocalCertificate; !slices.EqualFunc(got, certificate.Certificate, bytes.Equal) {
				t.Fatalf("server LocalCertificate = %x, want %x", got, certificate.Certificate)
			}
		})
	}
}

func TestGo127SignatureSchemeVersionFiltering(t *testing.T) {
	if slices.Contains(new(Config).signatureSchemes(VersionTLS12, VersionTLS12), MLDSA65) {
		t.Fatal("TLS 1.2 signature schemes contain ML-DSA")
	}
	if !slices.Contains(new(Config).signatureSchemes(VersionTLS13, VersionTLS13), MLDSA65) {
		t.Fatal("TLS 1.3 signature schemes do not contain ML-DSA")
	}
	if !slices.Contains(new(Config).signatureSchemes(VersionTLS12, VersionTLS13), MLDSA65) {
		t.Fatal("TLS 1.2-1.3 signature schemes do not contain ML-DSA")
	}
}

func TestGo127KeyLogWriterError(t *testing.T) {
	var file *os.File
	err := (&Config{KeyLogWriter: file}).writeKeyLog("CLIENT_RANDOM", make([]byte, 32), make([]byte, 48))
	if !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("writeKeyLog error = %v, want os.ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "KeyLogWriter") {
		t.Fatalf("writeKeyLog error lacks context: %v", err)
	}
}

func TestGo127X509KeyPairAlwaysPopulatesLeaf(t *testing.T) {
	t.Setenv("GODEBUG", "x509keypairleaf=0")
	certificate, _, _, _ := standardInteropCertificate(t)
	if certificate.Leaf == nil {
		t.Fatal("X509KeyPair left Certificate.Leaf nil")
	}
}

func TestGo127KeyUpdateSpamDoesNotAdvanceRecordState(t *testing.T) {
	certificate, _, leaf, _ := standardInteropCertificate(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	clientSide, serverSide := go127Pipe(t)

	clientResult := make(chan error, 1)
	go func() {
		client := Client(clientSide, &Config{
			RootCAs:                roots,
			ServerName:             "standard.test",
			MinVersion:             VersionTLS13,
			MaxVersion:             VersionTLS13,
			CipherSuitesTLS13:      []uint16{TLS_AES_128_GCM_SHA256},
			CurvePreferences:       []CurveID{X25519},
			SignatureSchemes:       []SignatureScheme{ECDSAWithP256AndSHA256},
			SessionTicketsDisabled: true,
		})
		if err := client.Handshake(); err != nil {
			clientResult <- err
			return
		}
		keyUpdate, err := (&keyUpdateMsg{}).marshal()
		if err != nil {
			clientResult <- err
			return
		}
		suite := cipherSuiteTLS13ByID(client.cipherSuite)
		for range maxUselessRecords + 1 {
			_, _ = client.writeRecordLocked(recordTypeHandshake, keyUpdate)
			client.setWriteTrafficSecret(suite, suite.nextTrafficSecret(client.out.trafficSecret))
		}
		clientResult <- nil
	}()

	server := Server(serverSide, &Config{
		Certificates:           []Certificate{certificate},
		MinVersion:             VersionTLS13,
		MaxVersion:             VersionTLS13,
		CipherSuitesTLS13:      []uint16{TLS_AES_128_GCM_SHA256},
		CurvePreferences:       []CurveID{X25519},
		SignatureSchemes:       []SignatureScheme{ECDSAWithP256AndSHA256},
		SessionTicketsDisabled: true,
	})
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}
	const want = "tls: too many non-advancing records"
	if _, err := server.Read(make([]byte, 1)); err == nil || err.Error() != want {
		t.Fatalf("server.Read error = %v, want %q", err, want)
	}
	if err := <-clientResult; err != nil {
		t.Fatalf("client key updates: %v", err)
	}
}
