# Experimental GOST TLS 1.3 candidate

This branch adds an opt-in `gost_tls13_gosuslugi` client strategy and a separate GOST TLS listener. The strategy is registered only when explicitly selected with `-strategy gost_tls13_gosuslugi`. The client connects to the configured server address at the explicitly configured GOST port, sends SNI `www.gosuslugi.ru`, requires RFC 9367 GOST TLS 1.3, verifies the server leaf certificate by its exact SHA-256 DER pin, then starts the existing TypeMux/smux TiredVPN stream. It does not use Gosuslugi credentials or certificates.

## Local canary configuration

Server: provide a server-owned GOST certificate and PKCS #8 private key, then set all three options. For example, `-gost-listen 127.0.0.1:12444 -gost-cert /etc/tiredvpn/gost-server.crt -gost-key /etc/tiredvpn/gost-server.key`. The GOST listener is disabled unless all three values are present and binds independently from the normal listener.

Client: calculate the SHA-256 digest of the leaf certificate's DER bytes (for PEM input: `openssl x509 -in gost-server.crt -outform DER | sha256sum`) and set both `-gost-tls13-pin <64-hex-digest>` and `-gost-tls13-port 12444`; select explicitly with `-strategy gost_tls13_gosuslugi`. The pin covers the full leaf certificate, so renewing that certificate requires updating client configs. Never use `-insecure` or omit the pin.

No deployment has been performed. Do not treat this as ready for a public listener until G0/G1 interoperability gates are closed, Android builds are verified, and a dedicated canary plan has passed review.

## Verification performed

- Local GOST TLS 1.3 handshake using the candidate library at both ends.
- Exact certificate pin accepted; wrong pin rejected.
- TypeMux/smux echo round-trip.
- Server-side GOST TLS ingress integration test negotiates a GOST suite and dispatches TypeMux/smux on the dedicated handler.
- Strategy/server/client/CLI package compile and focused tests.
- Earlier full `internal/strategy`, `internal/server`, `internal/client`, and CLI test run: strategy, client and CLI passed; server suite had two unrelated environment/timing failures: IPv6 unavailable (`TestWildcardListenersCoexist`) and a flaky timing assertion (`TestB1GateCostIsFlatInClientCount`). The final isolated candidate tests were rerun after the dedicated-listener changes and passed.

## Still required

- Independent GOST TLS peer interoperability and real compatible Gosuslugi client profile comparison.
- Malformed/truncated handshake and deadline/cancellation cases.
- Linux release build matrix and Android JNI/ABI build with Go 1.27.1.
- pcap comparison on Rostelecom, dedicated isolated canary, and controlled A/B measurements.
