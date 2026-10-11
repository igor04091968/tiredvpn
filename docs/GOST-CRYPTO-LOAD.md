# GOST TLS handshake load test

Opt-in Linux loopback test for the GOST TLS server path:

```bash
TIREDVPN_RUN_GOST_HANDSHAKE_LOAD=1 go test ./internal/server -run '^TestGOSTHandshakeLoad$' -count=1 -v
```

The default run steps through 1, 8, 32, 128 and 256 parallel connections. To test higher levels, set `TIREDVPN_GOST_HANDSHAKE_LOAD_MAX` to a value up to the server's 4096-connection admission limit:

```bash
TIREDVPN_RUN_GOST_HANDSHAKE_LOAD=1 TIREDVPN_GOST_HANDSHAKE_LOAD_MAX=4096 go test ./internal/server -run '^TestGOSTHandshakeLoad$' -count=1 -v
```

The server runs in the test process. A child process uses the project's GOST TLS implementation to make real TLS 1.3 handshakes, verifies the negotiated GOST cipher suite, sends the mux discriminator and holds sessions briefly so the server's peak resources can be sampled. Client cryptographic work is in the child process, so reported CPU time, RSS, goroutines and active connections describe the server process. The generated test certificate and key are ephemeral. Informational logs are suppressed during this opt-in test to keep per-handshake logging from dominating the measurements; production logging overhead is therefore excluded.

## Recorded run

Loopback run on 2026-10-11, AMD Ryzen 3 3200U, 4 logical CPUs, Linux 7.0.0-30-generic. Admission limit was 4096. Every attempted connection completed a GOST TLS 1.3 handshake and mux setup; no connection was rejected.

| Parallel handshakes | Throughput | Handshake p50 | p90 | p99 | Max | Server CPU user/system | Server RSS peak above phase baseline | Goroutines above baseline |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 128 | 125/s | 475 ms | 507 ms | 524 ms | 549 ms | 651/110 ms | 2.2 MiB | 643 |
| 256 | 195/s | 641 ms | 763 ms | 832 ms | 847 ms | 975/152 ms | 11.8 MiB | 1,283 |
| 512 | 313/s | 872 ms | 1,015 ms | 1,074 ms | 1,092 ms | 1,467/280 ms | 7.7 MiB | 2,563 |
| 1,024 | 372/s | 1,202 ms | 1,731 ms | 1,931 ms | 1,989 ms | 3,013/495 ms | 34.4 MiB | 5,123 |
| 2,048 | 315/s | 2,924 ms | 4,901 ms | 5,289 ms | 5,499 ms | 6,363/944 ms | 33.6 MiB | 10,243 |
| 4,096 | 379/s | 5,275 ms | 8,508 ms | 9,347 ms | 9,591 ms | 12,898/1,737 ms | 97.8 MiB | 20,483 |

At the 4096 limit, the server held all 4096 active connections and used about 14.6 CPU-seconds over 10.8 seconds of wall time. Peak RSS rose by about 98 MiB and p99 handshake latency reached 9.35 seconds. This is sufficient reason to evaluate a separate, configurable GOST-handshake admission limit: the general TCP cap permits a large burst of expensive negotiations. The run does not establish the right production limit; that needs a target-server run under its CPU, memory, client arrival rate and normal logging configuration.

These are one-machine loopback measurements, not production capacity guarantees. The test covers successful GOST handshakes, not malformed ClientHellos, packet loss, external network latency or a sustained arrival rate. RSS deltas can vary across phases because the Go allocator retains memory. The benchmark deliberately suppresses informational logs and uses an ephemeral certificate, so it should be repeated on each target server before choosing a limit.
