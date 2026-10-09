package gosttls

import (
	"slices"
	"testing"
)

func TestGo127CipherSuiteDefaults(t *testing.T) {
	legacy := []uint16{
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	for _, godebug := range []string{"", "tlsrsakex=1,tls3des=1"} {
		t.Run(godebug, func(t *testing.T) {
			t.Setenv("GODEBUG", godebug)
			defaults := new(Config).cipherSuites(true)
			for _, id := range legacy {
				if slices.Contains(defaults, id) {
					t.Fatalf("default cipher suites contain legacy suite %x", id)
				}
			}
		})
	}

	explicit := (&Config{CipherSuites: legacy}).cipherSuites(true)
	for _, id := range legacy {
		if !slices.Contains(explicit, id) {
			t.Fatalf("explicit cipher suites do not contain legacy suite %x", id)
		}
	}
}

func TestGo127MLKEM1024IsOptIn(t *testing.T) {
	if slices.Contains(new(Config).curvePreferences(VersionTLS13), MLKEM1024) {
		t.Fatal("MLKEM1024 is enabled by default")
	}
	if got := (&Config{CurvePreferences: []CurveID{MLKEM1024}}).curvePreferences(VersionTLS13); !slices.Equal(got, []CurveID{MLKEM1024}) {
		t.Fatalf("explicit MLKEM1024 preferences = %v", got)
	}
}

func TestGo127RemovedVersionGODEBUG(t *testing.T) {
	t.Setenv("GODEBUG", "tls10server=1")
	if slices.Contains(new(Config).supportedVersions(roleServer), VersionTLS10) {
		t.Fatal("tls10server=1 changed the default minimum TLS version")
	}
}
