# Tele2 field test, 8 October 2026

The client used Tele2 mobile data from a tablet connected to the laptop over
Bluetooth PAN. The tablet's Wi-Fi was off. The test ran in an isolated network
namespace, leaving the laptop's main connection and routes in place.

Each check forced one strategy with fallback disabled. A temporary local SOCKS
proxy sent a request through the tunnel to an API on the server's loopback
interface. The expected HTTP 401 response confirmed that the tunnel carried
application data to the server and back.

| Strategy | Server endpoints | Result |
|----------|------------------|--------|
| `reality_singleflight` | `gw`, `gw2` | 2/2 passed |
| `gost_tls13_gosuslugi` | `gw`, `gw2` | 2/2 passed |

These are separate builds: `reality_singleflight` is in this branch and
[`v1.11.5-igor.1`](https://github.com/igor04091968/tiredvpn/releases/tag/v1.11.5-igor.1);
`gost_tls13_gosuslugi` is in the
[`v1.12.1-igor.1` core release](https://github.com/igor04091968/tiredvpn/releases/tag/v1.12.1-igor.1).
The two strategies have not been combined in one release.

The full sweep, including those four checks, passed 69 of 73 requests across
`gw`, `gw2`, and a canary endpoint. Three failures were raw `quic` checks: that
wire mode is incompatible with these servers' Salamander configuration. One
`quic_salamander` request to `gw` timed out. Excluding the three incompatible
raw QUIC checks leaves 69/70 passed. Two earlier short Tele2 runs each passed
5/6 checks; their failed check was `quic_salamander` on `gw2`. A Wi-Fi control
run passed all six checks. The differing endpoints and control result do not
establish the cause of the intermittent timeout.

These results confirm working connections and data transfer for the two added
strategies on Tele2 in this test setup. They are point-in-time checks, not a
measurement of uptime, throughput, or resistance to active filtering.
