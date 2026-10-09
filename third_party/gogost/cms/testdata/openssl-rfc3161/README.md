# OpenSSL RFC 3161 test fixture

Generated with OpenSSL 3.2.0 on 2026-09-26. `request.tsq` timestamps the
30-byte `message.txt`; `response.tsr` contains the signed response and
the self-signed, test-only TSA certificate in `tsa.crt`. OpenSSL
`ts -verify -queryfile request.tsq -in response.tsr -CAfile tsa.crt`
reported `Verification: OK`.

The disposable RSA private key used to create the response is not included.
The certificate is a fixture, not a trusted root.
