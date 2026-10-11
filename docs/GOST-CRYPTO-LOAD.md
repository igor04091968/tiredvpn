# GOST TLS handshake load test

Opt-in Linux loopback test for the GOST TLS server path:

```bash
TIREDVPN_RUN_GOST_HANDSHAKE_LOAD=1 go test ./internal/server -run '^TestGOSTHandshakeLoad$' -count=1 -v
```

The default run steps through 1, 8, 32, 128 and 256 parallel connections. To test higher levels, set `TIREDVPN_GOST_HANDSHAKE_LOAD_MAX` to a value up to the server's 4096-connection admission limit. The test's GOST-handshake semaphore uses the production default of 512:

```bash
TIREDVPN_RUN_GOST_HANDSHAKE_LOAD=1 TIREDVPN_GOST_HANDSHAKE_LOAD_MAX=4096 go test ./internal/server -run '^TestGOSTHandshakeLoad$' -count=1 -v
```

The server runs in the test process. A child process uses the project's GOST TLS implementation to make real TLS 1.3 handshakes, verifies the negotiated GOST cipher suite, sends the mux discriminator and holds sessions briefly so the server's peak resources can be sampled. Client cryptographic work is in the child process, so reported CPU time, RSS, goroutines and active connections describe the server process. The generated test certificate and key are ephemeral. Informational logs are suppressed during this opt-in test to keep per-handshake logging from dominating the measurements; production logging overhead is therefore excluded.

## Uncapped baseline

Two loopback baseline runs on 2026-10-11, AMD Ryzen 3 3200U, 4 logical CPUs, Linux 7.0.0-30-generic. These runs predate the dedicated GOST-handshake semaphore and measure the previous behavior: only the shared 4096 TCP admission limit was active. Every attempted connection completed a GOST TLS 1.3 handshake and mux setup; no connection was rejected.

| Parallel handshakes | Throughput | Handshake p50 | p90 | p99 | Max | Server CPU user/system | Server RSS peak above phase baseline | Goroutines above baseline |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 128 | 125/s | 475 ms | 507 ms | 524 ms | 549 ms | 651/110 ms | 2.2 MiB | 643 |
| 256 | 195/s | 641 ms | 763 ms | 832 ms | 847 ms | 975/152 ms | 11.8 MiB | 1,283 |
| 512 | 313/s | 872 ms | 1,015 ms | 1,074 ms | 1,092 ms | 1,467/280 ms | 7.7 MiB | 2,563 |
| 1,024 | 372/s | 1,202 ms | 1,731 ms | 1,931 ms | 1,989 ms | 3,013/495 ms | 34.4 MiB | 5,123 |
| 2,048 | 315/s | 2,924 ms | 4,901 ms | 5,289 ms | 5,499 ms | 6,363/944 ms | 33.6 MiB | 10,243 |
| 4,096 | 379/s | 5,275 ms | 8,508 ms | 9,347 ms | 9,591 ms | 12,898/1,737 ms | 97.8 MiB | 20,483 |

At the 4096 limit, the server held all 4096 active connections and used about 14.6 CPU-seconds over 10.8 seconds of wall time. Peak RSS rose by about 98 MiB and p99 handshake latency reached 9.35 seconds.

Two full ladder runs showed the same broad tail-latency growth, but throughput was not stable enough to identify a precise saturation point:

| Parallel handshakes | Run A throughput / p99 | Run B throughput / p99 |
|---:|---:|---:|
| 1,024 | 354/s / 1.91 s | 372/s / 1.93 s |
| 2,048 | 403/s / 4.05 s | 315/s / 5.29 s |
| 4,096 | 281/s / 11.90 s | 379/s / 9.35 s |

This justifies a separate, configurable GOST-handshake limit while retaining the shared 4096 TCP cap. The current default is 512, selected as a conservative starting point below the range where tail latency rose sharply in both runs. It is not a proven production optimum; tune it with repeated runs on the target server under its CPU, memory, client arrival rate and normal logging configuration.

## Run with the 512-handshake cap

After adding `-gost-max-handshakes` (default 512), another 4096-client loopback run admitted all connections and completed all handshakes. The sampled GOST-handshake peak was exactly 512 while active TCP connections reached 4096:

| Parallel TCP connections | Throughput | Handshake p50 | p90 | p99 | Max | GOST handshakes peak | Server RSS peak above phase baseline |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 512 | 141/s | 1,922 ms | 2,388 ms | 2,563 ms | 2,796 ms | 372/512 | 21.4 MiB |
| 1,024 | 270/s | 1,946 ms | 2,697 ms | 2,874 ms | 2,897 ms | 512/512 | 12.5 MiB |
| 2,048 | 290/s | 3,280 ms | 4,880 ms | 5,413 ms | 5,904 ms | 512/512 | 50.2 MiB |
| 4,096 | 323/s | 5,732 ms | 8,576 ms | 9,268 ms | 9,528 ms | 512/512 | 84.6 MiB |

The limit controls concurrent TLS negotiations, and the integration test verifies the slot is free while the completed TLS connection is still waiting for its mux discriminator. It does not cap established sessions: the separate shared TCP limit still admitted 4096 active connections, so total goroutines and memory continued to grow with those sessions. At 4096 connections the p99 completion time remained high because clients waited in the bounded handshake queue. Reassess both limits against real arrival patterns and target-server resources before deployment.

These are one-machine loopback measurements, not production capacity guarantees. The test covers successful GOST handshakes, not malformed ClientHellos, packet loss, external network latency or a sustained arrival rate. RSS deltas can vary across phases because the Go allocator retains memory. The benchmark deliberately suppresses informational logs and uses an ephemeral certificate, so it should be repeated on each target server before choosing a limit.
