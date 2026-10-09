package gosttls

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
	x509 "gitverse.ru/uzer_007/gogost/v3/gostx509"
)

func benchmarkGOSTHandshake(
	b *testing.B,
	clientConfig, serverConfig *Config,
) (ConnectionState, error) {
	clientSide, serverSide := net.Pipe()
	deadline := time.Now().Add(30 * time.Second)
	_ = clientSide.SetDeadline(deadline)
	_ = serverSide.SetDeadline(deadline)

	serverResult := make(chan error, 1)
	go func() {
		server := Server(serverSide, serverConfig)
		err := server.Handshake()
		if err == nil {
			_, err = server.Write([]byte{1})
		}
		_ = serverSide.Close()
		serverResult <- err
	}()

	client := Client(clientSide, clientConfig)
	err := client.Handshake()
	if err == nil {
		var applicationData [1]byte
		_, err = io.ReadFull(client, applicationData[:])
	}
	state := client.ConnectionState()
	_ = clientSide.Close()
	serverErr := <-serverResult
	if err != nil {
		return state, err
	}
	return state, serverErr
}

func BenchmarkGOSTTLS13Handshake(b *testing.B) {
	certificate, leaf := testGOSTCertificate(b, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	for _, suite := range GOSTCipherSuiteIDs() {
		suite := suite
		b.Run(CipherSuiteName(suite), func(b *testing.B) {
			for _, resumed := range []bool{false, true} {
				name := "full"
				if resumed {
					name = "resumed"
				}
				b.Run(name, func(b *testing.B) {
					serverConfig := GOSTConfig(&Config{Certificates: []Certificate{certificate}})
					serverConfig.CipherSuitesTLS13 = []uint16{suite}
					serverConfig.CurvePreferences = []CurveID{GOSTCurve256A}
					clientConfig := GOSTConfig(&Config{RootCAs: roots, ServerName: "server.test"})
					clientConfig.CipherSuitesTLS13 = []uint16{suite}
					clientConfig.CurvePreferences = []CurveID{GOSTCurve256A}
					if resumed {
						clientConfig.ClientSessionCache = NewLRUClientSessionCache(4)
						state, err := benchmarkGOSTHandshake(b, clientConfig, serverConfig)
						if err != nil {
							b.Fatal(err)
						}
						if state.DidResume {
							b.Fatal("initial benchmark connection unexpectedly resumed")
						}
						state, err = benchmarkGOSTHandshake(b, clientConfig, serverConfig)
						if err != nil {
							b.Fatal(err)
						}
						if !state.DidResume {
							b.Fatal("benchmark session did not resume")
						}
					} else {
						serverConfig.SessionTicketsDisabled = true
						clientConfig.SessionTicketsDisabled = true
					}
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						state, err := benchmarkGOSTHandshake(b, clientConfig, serverConfig)
						if err != nil {
							b.Fatal(err)
						}
						if state.DidResume != resumed {
							b.Fatalf("DidResume=%v, want %v", state.DidResume, resumed)
						}
					}
				})
			}
		})
	}
}

func BenchmarkGOSTTLS13Record(b *testing.B) {
	certificate, leaf := testGOSTCertificate(b, "server.test", gost3410.CurveIdtc26gost341012256paramSetA())
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	for _, suite := range GOSTCipherSuiteIDs() {
		suite := suite
		b.Run(CipherSuiteName(suite), func(b *testing.B) {
			for _, size := range []int{1 << 10, 4 << 10, 16 << 10} {
				b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
					serverConfig := GOSTConfig(&Config{
						Certificates:           []Certificate{certificate},
						SessionTicketsDisabled: true,
					})
					serverConfig.CipherSuitesTLS13 = []uint16{suite}
					serverConfig.CurvePreferences = []CurveID{GOSTCurve256A}
					clientConfig := GOSTConfig(&Config{
						RootCAs:                roots,
						ServerName:             "server.test",
						SessionTicketsDisabled: true,
					})
					clientConfig.CipherSuitesTLS13 = []uint16{suite}
					clientConfig.CurvePreferences = []CurveID{GOSTCurve256A}

					clientSide, serverSide := net.Pipe()
					server := Server(serverSide, serverConfig)
					serverResult := make(chan error, 1)
					go func() {
						if err := server.Handshake(); err != nil {
							serverResult <- err
							return
						}
						_, err := io.Copy(io.Discard, server)
						serverResult <- err
					}()
					client := Client(clientSide, clientConfig)
					if err := client.Handshake(); err != nil {
						b.Fatal(err)
					}

					payload := make([]byte, size)
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						if _, err := client.Write(payload); err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
					_ = client.Close()
					if err := <-serverResult; err != nil {
						b.Fatal(err)
					}
				})
			}
		})
	}
}
