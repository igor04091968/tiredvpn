# GOST stalled-handshake admission test

An opt-in Linux loopback test exercises the TCP accept loop, shared admission semaphore, GOST handler, and 30-second handshake deadline:

```bash
TIREDVPN_RUN_ADMISSION_STRESS=1 go test ./internal/server -run '^TestGOSTAdmissionStress$' -count=1 -v
```

It opens the default 4096 admitted connections without sending ClientHello bytes, then sends 512 overflow connections. Each overflow socket must return EOF or TCP reset; a read timeout fails the test. The test records every slot's admission and release timestamps, waits for all handler completion events, and reports the full-capacity hold time and slot-hold duration distribution. The normal test suite skips this test unless the environment variable is set; an enabled run takes about 31 seconds.

## Recorded run

Local loopback run on 2026-10-11:

- 4096 stalled connections admitted; connection 4097 was rejected and closed. All 512 overflow sockets returned EOF or reset.
- The overflow burst completed in 73.9 ms (about 6,930 rejected connections/s) and used 14.6 ms of process user CPU. The first rejection was logged immediately; the other 511 were reported in one 10-second summary.
- Full capacity lasted 30.001 s. Individual slot holds were 30.000 s minimum, 30.001 s at p50, 30.001 s at p90, 30.002 s at p99, and 30.004 s maximum. All 4096 handler completion events arrived and the semaphore was empty.
- The Go test process RSS was 20.2 MiB before connection setup and 58.7 MiB with the connections open. `HeapAlloc` increased by 15.5 MiB and `HeapSys` by 37.0 MiB at capacity. After handlers exited and a GC, `HeapAlloc` was 3.4 MiB above baseline.
- The Prometheus counter `tiredvpn_admission_rejected_total` increased by 512. It is exposed by `/metrics` when the Redis-backed API is enabled.

These are measurements from one local run, not capacity guarantees. The test process contains both client and server TCP endpoints, so RSS is not a server-only per-connection measurement; kernel socket memory is not included in process RSS. The clients send no TLS bytes, so this tests idle/incomplete handshakes and timeout cleanup, not cryptographic CPU cost from valid or malformed ClientHello messages. There is no application-level ingress rate limit. Rejection logs are aggregated to one immediate warning followed by a count summary every 10 seconds while rejects continue; the Prometheus counter retains the total rejection count.
