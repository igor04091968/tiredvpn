# GOST stalled-handshake admission test

An opt-in Linux loopback test exercises the real TCP accept loop, shared admission semaphore, GOST handler, and 30-second handshake deadline:

```bash
TIREDVPN_RUN_ADMISSION_STRESS=1 go test ./internal/server -run '^TestGOSTAdmissionStress$' -count=1 -v
```

It opens the default 4096 admitted connections without sending ClientHello bytes, then sends another 512 connections and checks that overflow sockets are closed. It waits through the real handshake deadline and checks that all admission slots are released. The normal test suite skips this test unless the environment variable is set; an enabled run takes about 32 seconds.

## Recorded run

Local loopback run on 2026-10-11:

- 4096 stalled connections admitted; the 4097th was rejected and closed.
- 512 additional connections were closed at about 3,744 connections/s; the burst took about 137 ms and used about 35 ms of process user CPU. The accept loop emitted a warning for every rejected connection.
- The Go test process RSS was about 20.1 MiB before connection setup and 58.7 MiB with the connections open. `HeapSys` increased by about 37.3 MiB at capacity; after the handlers timed out and a GC, `HeapAlloc` was about 3.3 MiB above baseline.
- After the 30-second handshake deadline, all 4096 slots were released.

These are measurements from one local run, not capacity guarantees. The test process contains both client and server TCP endpoints, so RSS is not a server-only per-connection measurement; kernel socket memory is not included in process RSS. The clients send no TLS bytes, so this tests idle/incomplete handshakes and timeout cleanup, not cryptographic CPU cost from valid or malformed ClientHello messages. The accept loop emits one warning per overflow connection, and there is no application-level ingress rate limit.
