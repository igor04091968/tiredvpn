# Password PFX interoperability fixture

`password.p12` was created by `github.com/krotos139/go-gostcrypto`
at commit `409be1d9982195558ce16fabd5d0ad20454bee3c` using `pfx.Marshal`.
The test password is `interop-password`. The container uses PBES2 with
GOST 28147 CFB and CryptoPro key meshing, plus an HMAC-Streebog-512
container MAC. `cert.der` is public. The private key exists only inside
the password-protected test container and is for interoperability tests
only; it does not identify a real user.
