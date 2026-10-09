# GOST TLS 1.3 transport

The fork combines REALITY Single Flight with an opt-in GOST TLS 1.3 transport. The client connects to the configured TiredVPN server on a separate TCP listener, negotiates only RFC 9367 GOST suites, checks the server leaf certificate against one or two explicitly trusted SHA-256 DER pins and checks certificate validity before starting TypeMux/smux.

The ClientHello follows locally captured CryptoPro CSP 5.0 R4 samples. Fresh random values and key shares are generated on each connection. Post-handshake authentication and PSK-only resumption are omitted, so this is an approximation of that profile. See [the profile implementation](docs/gost-cryptopro-clienthello.md).

## Configuration

Server: provide a server-owned GOST certificate and PKCS #8 private key, then set all three options: `-gost-listen 127.0.0.1:12444 -gost-cert /etc/tiredvpn/gost-server.crt -gost-key /etc/tiredvpn/gost-server.key`. The dedicated listener is disabled unless all options are set. Keep the key private and choose the bind address for the intended deployment.

Client: compute the full leaf DER digest with `openssl x509 -in gost-server.crt -outform DER | sha256sum`, then set `-gost-tls13-pin PIN -gost-tls13-port 12444 -strategy gost_tls13_gosuslugi`. The pin covers the full certificate, including a same-key renewal. Two pins can overlap during rotation as described below. There is no insecure trust fallback for this transport.

## Certificate rotation with two trusted pins

The client option `-gost-tls13-pin` accepts one SHA-256 leaf DER digest, or two distinct digests separated by a comma: `-gost-tls13-pin OLD_PIN,NEW_PIN`. Each digest must contain exactly 64 hexadecimal characters. Empty entries, duplicate pins and more than two pins are rejected. Whitespace around a digest and uppercase hex are accepted.

Trust is restricted to these explicitly configured certificates. Both pins have equal trust during the overlap; the peer cannot add or replace a pin. The client still checks the certificate validity period. It never switches to an unverified certificate or to a public-key-only match. Reissuing a certificate with the same key changes its full DER pin.

For a planned rotation:

1. Generate the replacement certificate and calculate its SHA-256 DER pin locally. Transfer the pin to the operator and clients through the existing trusted configuration channel. Do not learn it from an unauthenticated connection to the server.
2. Install a client build that supports two pins, then distribute `OLD_PIN,NEW_PIN` while the server still uses the old certificate. Confirm that every client which must retain access received the update.
3. Replace the server certificate and key using the normal backup/restart procedure. Confirm that updated clients connect and complete pinned GOST TLS and authenticated tunnel checks.
4. After the planned overlap, distribute only `NEW_PIN`. Verify that the old certificate is refused and remove the old key from active use.

On Android the existing `gostPin` URL parameter and `gostTls13Pin` JSON field carry the same comma-separated string. Import/export preserve both pins. A profile with one pin remains compatible. APK `1.12.1-igor.4` and core `v1.12.2-igor.4` support two pins. Previous `.3` releases accept only one pin; upgrade clients before distributing dual-pin profiles. No certificate or production profile is changed automatically by this implementation.

## Releases and deployment state

[Core v1.12.2-igor.4](https://github.com/igor04091968/tiredvpn/releases/tag/v1.12.2-igor.4) and [Android v1.12.1-igor.4](https://github.com/igor04091968/tiredvpn-android/releases/tag/v1.12.1-igor.4) contain the client pin-rotation change. The Android native core is pinned to fce4f440843f0f0fad3cacdb236f5729a489f5be.

Production nodes were updated to server 1.12.2-igor.3 on 2026-10-09. Their ordinary TCP/UDP listener is 12443 and dedicated GOST TCP listener is 12444. Publishing `.4` does not replace running binaries or certificates. Two-pin verification is a client feature; existing servers remain compatible. Backups and node-specific rollback instructions are kept in the operator's private technology document.

## Verification and limits

- GOST handshake and TypeMux/smux echo with one pin and either position of a two-pin list.
- Unknown certificates, same-key renewal without its new pin, removal of the old pin, expired/future certificates, malformed DER and empty certificate chains are refused.
- Invalid, empty, repeated and excessive pins are rejected. Android JSON and URL import/export retain both explicitly configured pins; JNI forwarding retains the complete value.
- Go focused tests with the race detector and go vet passed. The Android configuration/import suite passed 56 tests.
- ClientHello wire structure, fresh key shares, HelloRetryRequest and refusal of AES suites have regression coverage. Android socket protection runs before TCP connect.
- Before/after the 2026-10-09 server rollout, both nodes passed new/old GOST, REALITY, Single Flight and QUIC Salamander tunnel checks.

CryptoPro curl completed TLS 1.3 and HTTP checks against the server in the laboratory. Other peers had documented limitations, so these measurements do not establish universal interoperability. Android MTS operation and improved reliability under active filtering still require controlled field tests. Private packet captures, credentials and signing keys are excluded from the public repository.
