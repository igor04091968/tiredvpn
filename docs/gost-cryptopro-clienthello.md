# GOST client ClientHello profile

The opt-in `gost_tls13_gosuslugi` transport uses a ClientHello based on a
CryptoPro curl / CSP 5.0 R4 TLS 1.3 capture. The endpoint stays the configured
TiredVPN server. SNI remains `www.gosuslugi.ru`; no portal connection is made.

The local `third_party/gogost` copy keeps the cryptographic implementation and
changes the initial hello before transcript hashing. Client random, session ID,
GOST and P-256 shares are generated anew. The reference's order of cipher suites,
groups and signatures is retained. Two capabilities are intentionally omitted:
post-handshake client authentication, which is not implemented, and PSK-only
resumption. This profile therefore has a different JA3 from CryptoPro.

Only TLS 1.3 GOST cipher suites can be negotiated. A standard cipher advertised
in the template causes an explicit failure at ServerHello if selected. The
strategy still verifies the configured SHA-256 leaf certificate pin and validity
period before mux dispatch. Probe and Connect protect Android sockets before SYN.
The server's profile and all other strategies are unchanged.

Validation:

```sh
go -C third_party/gogost test ./gosttls -run 'TestCryptoPro|TestGOSTConfigUsesStrict' -count=1 -timeout=60s
go test ./internal/strategy -run 'TestNewGOST|TestGOSTTLS|TestGOSTSocket' -count=1 -timeout=60s
```

Wire tests check record version, extension order, two key shares and fresh hello
bytes. Handshake tests cover GOST, a GOST HelloRetryRequest, AES refusal, wrong pin
and mux echo. Deployment requires a new Android native library and APK; existing
servers accept the profile without an update. Compatibility checks on a working
access network do not establish effectiveness against filtering on mobile data.
