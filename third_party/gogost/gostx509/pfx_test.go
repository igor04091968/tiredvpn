package gostx509

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"gitverse.ru/uzer_007/gogost/v3/gost3410"
)

// RFC 9548 Appendix A.2.1: password-protected key, clear certificate.
const rfc9548PFXA2 = `MIIFKwIBAzCCBMQGCSqGSIb3DQEHAaCCBLUEggSxMIIErTCCAswGCSqGSIb3DQEH
AaCCAr0EggK5MIICtTCCArEGCyqGSIb3DQEMCgEDoIICSjCCAkYGCiqGSIb3DQEJ
FgGgggI2BIICMjCCAi4wggHboAMCAQICBAGMuoQwCgYIKoUDBwEBAwIwODENMAsG
A1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsyNjogR09TVCAzNC4xMC0xMiAyNTYt
Yml0MB4XDTAxMDEwMTAwMDAwMFoXDTQ5MTIzMTAwMDAwMFowOzENMAsGA1UEChME
VEsyNjEqMCgGA1UEAxMhT1JJR0lOQVRPUjogR09TVCAzNC4xMC0xMiA1MTItYml0
MIGgMBcGCCqFAwcBAQECMAsGCSqFAwcBAgECAQOBhAAEgYC0i7davCkOGGVcYqFP
tS1fUIROzB0fYARIe0tclTRpare/qzRuVRapqzzO+K21LDpYVfDPs2Sqa13ZN+Ts
/JUlv59qCFB2cYpFyB/0kh4+K79yvz7r8+4WE0EmZf8T3ae/J1Jo6xGunecH1/G4
hMts9HYLnxbwJDMNVGuIHV6gzqOBhzCBhDBjBgNVHSMEXDBagBSsbA5MRGaiQpbi
nwk7JWbzy6RTKqE8pDowODENMAsGA1UEChMEVEsyNjEnMCUGA1UEAxMeQ0EgVEsy
NjogR09TVCAzNC4xMC0xMiAyNTYtYml0ggQBjLqBMB0GA1UdDgQWBBR+BlcJmAyt
awioV+55AFg6ydegpDAKBggqhQMHAQEDAgNBAApeqfHQG6YvR5Pt5oDMiNFiIdey
K5a0qf5gdBe2czLfF1A9Q8M9ya658Xl53zLzgOQXVCfYQsg4DFQBrPyHBBAxVDAj
BgkqhkiG9w0BCRUxFgQUeVV0+dS25MICJChpmGc/8AoUwE0wLQYJKoZIhvcNAQkU
MSAeHgBwADEAMgBGAHIAaQBlAG4AZABsAHkATgBhAG0AZTCCAdkGCSqGSIb3DQEH
AaCCAcoEggHGMIIBwjCCAb4GCyqGSIb3DQEMCgECoIIBVzCCAVMwWQYJKoZIhvcN
AQUNMEwwKQYJKoZIhvcNAQUMMBwECKf4N7NMwugqAgIIADAMBggqhQMHAQEEAgUA
MB8GCSqFAwcBAQUCAjASBBAlmt2WDfaPJlsAs0mLKglzBIH1DMvEacbbWRNDVSnX
JLWygYrKoipdOjDA/2HEnBZ34uFOLNheUqiKpCPoFpbR2GBiVYVTVK9ibiczgaca
EQYzDXtcS0QCZOxpKWfteAlbdJLC/SqPurPYyKi0MVRUPROhbisFASDT38HDH1Dh
0dL5f6ga4aPWLrWbbgWERFOoOPyh4DotlPF37AQOwiEjsbyyRHq3HgbWiaxQRuAh
eqHOn4QVGY92/HFvJ7u3TcnQdLWhTe/lh1RHLNF3RnXtN9if9zC23laDZOiWZplU
yLrUiTCbHrtn1RppPDmLFNMt9dJ7KKgCkOi7Zm5nhqPChbywX13wcfYxVDAjBgkq
hkiG9w0BCRUxFgQUeVV0+dS25MICJChpmGc/8AoUwE0wLQYJKoZIhvcNAQkUMSAe
HgBwADEAMgBGAHIAaQBlAG4AZABsAHkATgBhAG0AZTBeME4wCgYIKoUDBwEBAgME
QAkBKw4ihn7pSIYTEhu0bcvTPZjI3WgVxCkUVlOsc80G69EKFEOTnObGJGSKJ51U
KkOsXF0a7+VBZf3BcVVQh9UECIVEtO+VpuskAgIIAA==`

func TestRFC9548PFXA2(t *testing.T) {
	compact := bytes.Join(bytes.Fields([]byte(rfc9548PFXA2)), nil)
	der, err := base64.StdEncoding.DecodeString(string(compact))
	if err != nil {
		t.Fatal(err)
	}
	key, cert, chain, err := ParsePFX(der, "Пароль для PFX")
	if err != nil {
		t.Fatal(err)
	}
	if key == nil || cert == nil || len(chain) != 0 {
		t.Fatal("incomplete RFC 9548 PFX")
	}
}

// RFC 9548 Appendix A.3.1: both the key and certificate are encrypted.
const rfc9548PFXA3 = `MIIFjAIBAzCCBSUGCSqGSIb3DQEHAaCCBRYEggUSMIIFDjCCA0EGCSqGSIb3DQEH
BqCCAzIwggMuAgEAMIIDJwYJKoZIhvcNAQcBMFUGCSqGSIb3DQEFDTBIMCkGCSqG
SIb3DQEFDDAcBAgUuSVGsSwGjQICCAAwDAYIKoUDBwEBBAIFADAbBgkqhQMHAQEF
AQIwDgQM9Hk3dagtS48+G/x+gIICwWGPqxxN+sTrKbruRf9R5Ya9cf5AtO1frqMn
f1eULfmZmTg/BdE51QQ+Vbnh3v1kmspr6h2+e4Wli+ndEeCWG6A6X/G22h/RAHW2
YrVmf6cCWxW+YrqzT4h/8RQL/9haunD5LmHPLVsYrEai0OwbgXayDSwARVJQLQYq
sLNmZK5ViN+fRiS5wszVJ3AtVq8EuPt41aQEKwPy2gmH4S6WmnQRC6W7aoqmIifF
PJENJNn5K2M1J6zNESs6bFtYNKMArNqtvv3rioY6eAaaLy6AV6ljsekmqodHmQjv
Y4eEioJs0xhpXhZY69PXT+ZBeHv6MSheBhwXqxAd1DqtPTafMjNK8rqKCap9TtPG
vONvo5W9dgwegxRRQzlum8dzV4m1W9Aq4W7t8/UcxDWRz3k6ijFPlGaA9+8ZMTEO
RHhBRvM6OY2/VNNxbgxWfGYuPxpSi3YnCZIPmBEe5lU/Xv7KjzFusGM38F8YR61k
4/QNpKI1QUv714YKfaUQznshGGzILv1NGID62pl1+JI3vuawi2mDMrmkuM9QFU9v
/kRP+c2uBHDuOGEUUSNhF08p7+w3vxplatGWXH9fmIsPBdk2f3wkn+rwoqrEuijM
I/bCAylU/M0DMKhAo9j31UYSZdi4fsfRWYDJMq/8FPn96tuo+oCpbqv3NUwpZM/8
Li4xqgTHtYw/+fRG0/P6XadNEiII/TYjenLfVHXjAHOVJsVeCu/t3EsMYHQddNCh
rFk/Ic2PdIQOyB4/enpW0qrKegSbyZNuF1WI4zl4mI89L8dTQBUkhy45yQXZlDD8
k1ErYdtdEsPtz/4zuSpbnmwCEIRoOuSXtGuJP+tbcWEXRKM2UBgi3qBjpn7DU18M
tsrRM9pDdadl8mT/Vfh9+B8dZBZVxgQu70lMPEGexbUkYHuFCCnyi9J0V92StbIz
Elxla1VebjCCAcUGCSqGSIb3DQEHAaCCAbYEggGyMIIBrjCCAaoGCyqGSIb3DQEM
CgECoIIBQzCCAT8wVQYJKoZIhvcNAQUNMEgwKQYJKoZIhvcNAQUMMBwECP0EQk0O
1twvAgIIADAMBggqhQMHAQEEAgUAMBsGCSqFAwcBAQUBATAOBAzwxSqgAAAAAAAA
AAAEgeUqj9mI3RDfK5hMd0EeYws7foZK/5ANr2wUhP5qnDjAZgn76lExJ+wuvlnS
9PChfWVugvdl/9XJgQvvr9Cu4pOh4ICXplchcy0dGk/MzItHRVC5wK2nTxwQ4kKT
kG9xhLFzoD16dhtqX0+/dQg9G8pE5EzCBIYRXLm1Arcz9k7KVsTJuNMjFrr7EQuu
Tr80ATSQOtsq50zpFyrpznVPGCrOdIjpymZxNdvw48bZxqTtRVDxCYATOGqz0pwH
ClWULHD9LIajLMB2GhBKyQw6ujIlltJs0T+WNdX/AT2FLi1LFSS3+Cj9MVQwIwYJ
KoZIhvcNAQkVMRYEFHlVdPnUtuTCAiQoaZhnP/AKFMBNMC0GCSqGSIb3DQEJFDEg
Hh4AcAAxADIARgByAGkAZQBuAGQAbAB5AE4AYQBtAGUwXjBOMAoGCCqFAwcBAQID
BEDp4e22JmXdnvR0xA99yQuzQuJ8pxBeOpsLm2dZQqt3Fje5zqW1uk/7VOcfV5r2
bKm8nsLOs2rPT8hBOoeAZvOIBAjGIUHw6IjG2QICCAA=`

func TestRFC9548PFXA3(t *testing.T) {
	compact := bytes.Join(bytes.Fields([]byte(rfc9548PFXA3)), nil)
	der, err := base64.StdEncoding.DecodeString(string(compact))
	if err != nil {
		t.Fatal(err)
	}
	key, cert, chain, err := ParsePFX(der, "Пароль для PFX")
	if err != nil {
		t.Fatal(err)
	}
	if key == nil || cert == nil || len(chain) != 0 {
		t.Fatal("incomplete RFC 9548 PFX")
	}
}

func TestPasswordPFX(t *testing.T) {
	curve := gost3410.CurveIdtc26gost34102012256paramSetA()
	private, public := generateKey(t, curve)
	now := time.Now()
	template := &Certificate{SerialNumber: big.NewInt(19), Subject: pkix.Name{CommonName: "PFX"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: KeyUsageDigitalSignature, BasicConstraintsValid: true}
	certDER, err := CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range []*EncryptedPKCS8Options{nil, {Legacy28147: true}} {
		pfx, err := MarshalPFXWithOptions(private, cert, nil, "пароль", options)
		if err != nil {
			t.Fatal(err)
		}
		key, gotCert, chain, err := ParsePFX(pfx, "пароль")
		if err != nil {
			t.Fatal(err)
		}
		gotKey, ok := key.(*gost3410.PrivateKey)
		if !ok || !bytes.Equal(gotKey.Raw(), private.Raw()) || !bytes.Equal(gotCert.Raw, cert.Raw) || len(chain) != 0 {
			t.Fatal("PFX contents changed")
		}
		if _, _, _, err := ParsePFX(pfx, "wrong"); err == nil {
			t.Fatal("wrong password accepted")
		}
		pfx[len(pfx)-20] ^= 1
		if _, _, _, err := ParsePFX(pfx, "пароль"); err == nil {
			t.Fatal("tampered PFX accepted")
		}
	}
	other, _ := generateKey(t, curve)
	if _, err := MarshalPFX(other, cert, nil, "пароль"); err == nil {
		t.Fatal("mismatched key/cert accepted")
	}
}
