# OpenSSL GOST 2012 CMS EnvelopedData fixtures

Generated on a Linux test host with OpenSSL 3.5.2 and its `gost` engine on
2026-09-26. All recipients use synthetic test keys. `recipient.der` and
`recipient512.der` contain public certificates only. Their private scalars are
reconstructed by the tests from fixed, non-secret byte sequences.

The independent OpenSSL commands used `cms -encrypt -binary -engine gost` with
`-kuznyechik-ctr-acpkm` for `modern-envelope.der` and
`modern-envelope-512.der`, and `-magma-ctr-acpkm` for
`modern-envelope-magma.der`. `-binary` preserves the LF byte in
`modern-content.txt`.

The 256-bit certificates use the TC26 256-bit parameter set B. The 512-bit
certificate uses the TC26 512-bit parameter set A. No private key file from
the server is included.

`TestOpenSSLDecryptOurModernCMS` is an opt-in integration test. It creates
temporary keys on the OpenSSL host and verifies small Go-to-OpenSSL envelopes
and large OpenSSL-to-Go envelopes for Kuznyechik with 256/512-bit keys and
Magma with a 256-bit key. The
current gost-engine CMS decrypt path corrupts plaintext after its default
4 KiB Kuznyechik or 1 KiB Magma rekeying boundary when the CMS parameter
specifies a larger section; see [gost-engine issue 529](https://github.com/gost-engine/engine/issues/529).
