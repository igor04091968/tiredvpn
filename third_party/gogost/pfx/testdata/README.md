The A.4 files come from R 1323565.1.041-2022, Appendix A.4, as published at
https://meganorm.ru/mega_doc/norm/prikaz/25/r_1323565_1_041-2022_rekomendatsii_po_standartizatsii.html.

The HTML transcription of the container has two `1`/`l` substitutions:

- At Base64 character 14, `1` was corrected to `l`. The published ASN.1
  breakdown says the nested ContentInfo has length 2640 (0x0a50), whereas the
  uncorrected Base64 encodes length 2896 (0x0b50).
- At Base64 character 506, `l` was corrected to `1`. This changes one byte of
  the embedded certificate from `5e` to `5f` and makes the GOST 34.11-2012/256
  content digest equal to the signed messageDigest
  `d57380ccd6bbd7442e5ec9f9fb221fddc3538853903204e2051241cfc4ebe08d`.

The corrected fixture verifies with the GOST-enabled OpenSSL CMS verifier and
decrypts with the recipient key printed in A.4.2. No key or certificate bytes
were invented for this fixture.
