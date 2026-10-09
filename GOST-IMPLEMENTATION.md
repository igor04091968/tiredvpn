# Experimental GOST TLS 1.3 transport

This branch adds an opt-in `gost_tls13_gosuslugi` client strategy and a separate GOST TLS listener. The strategy is registered only when explicitly selected with `-strategy gost_tls13_gosuslugi`. The client connects to the configured server address at the explicitly configured GOST port, sends SNI `www.gosuslugi.ru`, requires RFC 9367 GOST TLS 1.3, verifies the server leaf certificate by its exact SHA-256 DER pin, then starts the existing TypeMux/smux TiredVPN stream. It does not use Gosuslugi credentials or certificates.

## Local canary configuration

Server: provide a server-owned GOST certificate and PKCS #8 private key, then set all three options. For example, `-gost-listen 127.0.0.1:12444 -gost-cert /etc/tiredvpn/gost-server.crt -gost-key /etc/tiredvpn/gost-server.key`. The GOST listener is disabled unless all three values are present and binds independently from the normal listener.

Client: calculate the SHA-256 digest of the leaf certificate's DER bytes (for PEM input: `openssl x509 -in gost-server.crt -outform DER | sha256sum`) and set both `-gost-tls13-pin <64-hex-digest>` and `-gost-tls13-port 12444`; select explicitly with `-strategy gost_tls13_gosuslugi`. The pin covers the full leaf certificate, so renewing that certificate requires updating client configs; the rotation procedure below allows an overlap. Never use `-insecure` or omit the pin.

## Certificate rotation with two trusted pins

The client option `-gost-tls13-pin` accepts one SHA-256 leaf DER digest, or two distinct digests separated by a comma: `-gost-tls13-pin OLD_PIN,NEW_PIN`. Each digest must contain exactly 64 hexadecimal characters. Empty entries, duplicate pins and more than two pins are rejected. Whitespace around a digest and uppercase hex are accepted.

Trust is restricted to these explicitly configured certificates. Both pins have equal trust during the overlap; the peer cannot add or replace a pin. The client still checks the certificate validity period. It never switches to an unverified certificate or to a public-key-only match. Reissuing a certificate with the same key changes its full DER pin.

For a planned rotation:

1. Generate the replacement certificate and calculate its SHA-256 DER pin locally. Transfer the pin to the operator and clients through the existing trusted configuration channel. Do not learn it from an unauthenticated connection to the server.
2. Install a client build that supports two pins, then distribute `OLD_PIN,NEW_PIN` while the server still uses the old certificate. Confirm that every client which must retain access received the update.
3. Replace the server certificate and key using the normal backup/restart procedure. Confirm that updated clients connect and complete pinned GOST TLS and authenticated tunnel checks.
4. After the planned overlap, distribute only `NEW_PIN`. Verify that the old certificate is refused and remove the old key from active use.

On Android the existing `gostPin` URL parameter and `gostTls13Pin` JSON field carry the same comma-separated string. Import/export preserve both pins. A profile with one pin remains compatible. APK `1.12.1-igor.3` and core tag `v1.12.2-igor.3` predate this change and accept only one pin; use a build containing the rotation change before distributing dual-pin profiles. No certificate or production profile is changed automatically by this implementation.

## Production deployment

On 2026-10-08, version `1.12.0-igor.1` was installed on `gw` and `gw2`. The
existing TCP/QUIC listener remains on port 12443; the opt-in GOST listener uses
TCP port 12444. Both nodes use the same operator-generated GOST certificate,
and the Android fork pins its SHA-256 DER fingerprint. The private key is
root-only on each node and is not in the repository or APK.

The deployment was tested from the Rostelecom-connected laptop over the public
network: the client negotiated GOST TLS 1.3, authenticated to the TiredVPN
server, and carried HTTPS requests to Telegram API, WhatsApp Web, and YouTube.
This confirms the deployed transport and data path. It does not demonstrate
that the strategy resists filtering on other networks or under active DPI.

Rollback on either node: restore `/opt/tiredvpn/tiredvpn.pre-gost-20261008` to
`/opt/tiredvpn/tiredvpn`, remove
`/etc/systemd/system/tiredvpn.service.d/30-gost-tls.conf`, then run
`systemctl daemon-reload` and `systemctl restart tiredvpn`. The original
listener and service configuration are preserved by that procedure.

## Verification performed

- Local GOST TLS 1.3 handshake using the candidate library at both ends.
- Exact certificate pin accepted; wrong pin rejected.
- TypeMux/smux echo round-trip.
- Server-side GOST TLS ingress integration test negotiates a GOST suite and dispatches TypeMux/smux on the dedicated handler.
- Live production round-trip through `gw2`: client reported GOST TLS 1.3, and HTTP requests returned Telegram API 302, WhatsApp 200, and YouTube 204. The temporary test client was deleted.
- Public TCP 12444 reachability verified separately for both nodes; both continue to serve the original listener on 12443.
- Strategy/server/client/CLI package compile and focused tests.
- Earlier full `internal/strategy`, `internal/server`, `internal/client`, and CLI test run: strategy, client and CLI passed; server suite had two unrelated environment/timing failures: IPv6 unavailable (`TestWildcardListenersCoexist`) and a flaky timing assertion (`TestB1GateCostIsFlatInClientCount`). The final isolated candidate tests were rerun after the dedicated-listener changes and passed.

## Still required

- Independent GOST TLS peer interoperability and comparison with the TLS profile of an actual Gosuslugi client.
- Malformed/truncated handshake and deadline/cancellation cases.
- Linux release build matrix and Android JNI/ABI build with Go 1.27.1.
- pcap comparison on Rostelecom, dedicated isolated canary, and controlled A/B measurements.
