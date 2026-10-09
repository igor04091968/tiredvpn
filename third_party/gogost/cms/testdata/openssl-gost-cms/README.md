# OpenSSL GOST CMS interoperability fixture

Generated on a Linux test host with OpenSSL 3.5.2 and the `gost` engine on
2026-09-26. `attached.p7m` and `detached.p7s` were signed by a freshly
generated GOST 2012/256 key, and both were verified by OpenSSL. The
certificate is self-signed and is supplied only as a public fixture;
its private key was deleted on the server before the public files were
transferred. `content.txt` is the detached document.
