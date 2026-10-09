# Independent CAdES-T fixture

`signed.p7s` was created with `github.com/krotos139/go-gostcrypto` at commit
`409be1d9982195558ce16fabd5d0ad20454bee3c` using its `cms.Sign` API.
The detached content is `content.txt`. Both signer and TSA use GOST
2012/256; the TSA certificate has a critical, exclusive timeStamping EKU.
The timestamp is on the CMS signature value. The fixture contains public
certificates only; no private keys are stored here. Certificates are
self-signed solely for deterministic interoperability checks and are not
trust anchors.
