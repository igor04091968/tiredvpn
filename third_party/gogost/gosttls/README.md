# gosttls

`gosttls` is a standalone, importable TLS implementation with RFC 9367 GOST
TLS 1.3 support. Its transport core is derived from Go's BSD-licensed
`crypto/tls` and synchronized with Go 1.27.1; the GOST extensions are
implemented inside this module and do not require a patched Go distribution
or changes to `GOROOT`.

See [`../docs/gost-tls.md`](../docs/gost-tls.md) for configuration, TCP and
`net/http` examples, certificate handling, and current limitations.
