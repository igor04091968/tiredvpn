# GOST TLS handshake load test

Opt-in Linux loopback test for the GOST TLS server path:

```bash
TIREDVPN_RUN_GOST_HANDSHAKE_LOAD=1 go test ./internal/server -run '^TestGOSTHandshakeLoad$' -count=1 -v
```

The default run steps through 1, 8, 32, 128 and 256 parallel connections. To test higher levels, set `TIREDVPN_GOST_HANDSHAKE_LOAD_MAX` to a value up to the server's 4096-connection admission limit. The current code default is 128; the historical 512-cap measurements below were made before that default was reduced:

```bash
TIREDVPN_RUN_GOST_HANDSHAKE_LOAD=1 TIREDVPN_GOST_HANDSHAKE_LOAD_MAX=4096 go test ./internal/server -run '^TestGOSTHandshakeLoad$' -count=1 -v
```

For a same-machine comparison at limits 128, 256, 512, 1024 and 4096 (the
shared TCP cap, so effectively uncapped for this workload), run the same
1024/2048/4096 connection series under each limit:

```bash
TIREDVPN_RUN_GOST_HANDSHAKE_LOAD=1 TIREDVPN_GOST_HANDSHAKE_LOAD_COMPARE=1 TIREDVPN_GOST_HANDSHAKE_LOAD_MAX=4096 go test ./internal/server -run '^TestGOSTHandshakeLoad$' -count=1 -v
```

The server runs in the test process. A child process uses the project's GOST TLS implementation to make real TLS 1.3 handshakes, verifies the negotiated GOST cipher suite, sends the mux discriminator and holds sessions briefly so the server's peak resources can be sampled. Client cryptographic work is in the child process, so reported CPU time, RSS, goroutines and active connections describe the server process. The generated test certificate and key are ephemeral. Informational logs are suppressed during this opt-in test to keep per-handshake logging from dominating the measurements; production logging overhead is therefore excluded.

The comparison test changes only the GOST handshake cap. It reports server CPU,
RSS, goroutines, throughput, latency, active TCP connections, and peak GOST
crypto concurrency. Repeat the complete matrix at least twice on target VPS
hardware before deployment; laptop data cannot establish a safe default for
one- or two-vCPU servers.

## Concurrent GOST handshake-limit comparison — two runs (2026-10-11)

Two comparison runs were completed on 2026-10-11 on the same Ryzen 3 3200U
(4 logical CPUs), Linux 7.0.0-30-generic host. Each cap was tested against
1024, 2048 and 4096 simultaneous clients, in ascending cap order. Cells show
`throughput / p99`; CPU and RSS are from the 4096-client phase. Run A used an
uncapped GOST limiter; with the shared TCP cap at 4096, this is the 4096-client
case. Run B explicitly set the GOST cap to 4096.

Run A:

| GOST cap | 1024 clients | 2048 clients | 4096 clients | CPU user/system ms | RSS increase |
|---:|---:|---:|---:|---:|---:|
| 128 | 318/s / 2.16 s | 300/s / 5.15 s | 273/s / 10.29 s | 13,122 / 2,243 | 102.1 MiB |
| 256 | 232/s / 3.05 s | 308/s / 4.87 s | 381/s / 8.26 s | 13,071 / 1,889 | 92.9 MiB |
| 512 | 315/s / 2.49 s | 362/s / 4.00 s | 354/s / 8.63 s | 13,016 / 1,957 | 50.9 MiB |
| 1024 | 264/s / 2.92 s | 347/s / 4.88 s | 351/s / 9.14 s | 13,552 / 1,943 | 139.6 MiB |
| 4096 (uncapped) | 329/s / 2.39 s | 326/s / 5.10 s | 358/s / 9.34 s | 13,993 / 2,011 | 57.2 MiB |

Run B:

| GOST cap | 1024 clients | 2048 clients | 4096 clients | CPU user/system ms | RSS increase |
|---:|---:|---:|---:|---:|---:|
| 128 | 301/s / 2.31 s | 354/s / 4.27 s | 239/s / 13.88 s | 14,850 / 2,313 | 101.9 MiB |
| 256 | 260/s / 3.09 s | 289/s / 5.12 s | 286/s / 10.97 s | 14,506 / 2,230 | 38.1 MiB |
| 512 | 279/s / 2.88 s | 193/s / 8.17 s | 292/s / 10.80 s | 14,802 / 2,169 | 75.7 MiB |
| 1024 | 230/s / 3.63 s | 264/s / 6.70 s | 269/s / 11.00 s | 14,953 / 2,107 | 89.9 MiB |
| 4096 (TCP cap) | 181/s / 4.34 s | 208/s / 7.46 s | 266/s / 12.04 s | 14,620 / 2,126 | 97.8 MiB |

Across both matrices, all 30 phases completed every handshake and rejected no connection. Throughput
and tail latency varied substantially between runs; because caps were tested
in ascending order, host heating or background load may also have affected
later profiles. The data supports bounding crypto concurrency, but does not
establish 512—or any other value—as optimal. Randomized profile order, cool-down
between runs, normal logging, and target-VPS CPU/RSS measurements remain
necessary before installation.

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

This supports a separate, configurable GOST-handshake limit while retaining the shared 4096 TCP cap. The two comparisons do not establish an optimal value: several profiles changed materially between runs, and the profiles were tested in ascending order. The current 128 default is a conservative starting point for the one-vCPU target VPSs, not a measured saturation point. Reassess it using target hardware, expected arrival rates and normal logging configuration.

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

## One-vCPU target VPS smoke — 2026-10-11

Before installing the release, the opt-in load test was run on each target VPS
with its `-gost-max-handshakes` default of 128 and loopback GOST TLS 1.3
clients. Each level ran once; all 169 handshakes on each node completed, no
connection was rejected, and the observed crypto-slot peak reached 128. The
client subprocess ran on the same one-vCPU VPS, so wall-clock throughput includes
client-side CPU contention. CPU and RSS columns report the server test process.
These figures check basic target-host behavior; they do not determine a safe
sustained arrival rate or prove Android network recovery.

| VPS | Parallel | Throughput | Handshake p50 / p99 | Server CPU user / sys | Server RSS peak |
|---|---:|---:|---:|---:|---:|
| gw2 | 1 | 1.4/s | 299 / 299 ms | 114 / 6 ms | 24.1 MiB |
| gw2 | 8 | 14.3/s | 124 / 129 ms | 35 / 1 ms | 25.3 MiB |
| gw2 | 32 | 51.2/s | 170 / 181 ms | 51 / 25 ms | 30.0 MiB |
| gw2 | 128 | 123.2/s | 469 / 518 ms | 257 / 8 ms | 30.9 MiB |
| gw | 1 | 0.7/s | 1,024 / 1,024 ms | 259 / 104 ms | 23.3 MiB |
| gw | 8 | 5.8/s | 760 / 772 ms | 171 / 234 ms | 25.0 MiB |
| gw | 32 | 33.1/s | 395 / 474 ms | 202 / 89 ms | 26.8 MiB |
| gw | 128 | 70.1/s | 922 / 1,033 ms | 600 / 96 ms | 29.2 MiB |

The test left both installed services and all client connections untouched.
The slower 128-client result on `gw` reflects this single same-host run; repeat
with remote clients and randomized caps before tuning above 128.
