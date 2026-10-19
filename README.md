# TiredVPN — fork

> Клиент-серверный VPN на Go с несколькими транспортами и настраиваемой стратегией подключения.

[![CI](https://github.com/igor04091968/tiredvpn/actions/workflows/ci.yml/badge.svg)](https://github.com/igor04091968/tiredvpn/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/igor04091968/tiredvpn)](https://github.com/igor04091968/tiredvpn/releases)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/igor04091968/tiredvpn)](go.mod)
![TiredVPN](img/github.png)

**Связанный проект:** [Android-клиент TiredVPN](https://github.com/igor04091968/tiredvpn-android).

## Изменения этого форка

| Стратегия | Реализация |
| --- | --- |
| REALITY Single Flight | Экспериментальный вариант REALITY: одновременно выполняется не более одного TLS-хэндшейка по всем donor SNI; начала разделены интервалом 450–600 мс. |
| ГОСТ TLS 1.3 | Экспериментальный отдельный TCP-транспорт на ГОСТ-криптографии. Профиль совместимости исследован в локальной лаборатории. Сертификат проверяется по сроку действия и одному или двум заранее указанным SHA-256 pin. |

Single Flight использует существующий REALITY-протокол. ГОСТ и Single Flight требуют явного выбора; наличие стратегий не означает, что подключение пройдёт через конкретную сеть. Проверки совместимости и передачи данных не измеряют устойчивость к блокировкам.

## Профиль ГОСТ

Работоспособность транспорта проверена в локальной лаборатории и полевых опытах. APK и сервер используют реализацию Go и библиотеку ГОСТ; исследовательские инструменты не входят в приложение. Полное совпадение с эталонным профилем и универсальная совместимость не заявляются. Подробные исследовательские материалы сохраняются приватно.

Клиент принимает только ГОСТ-наборы TLS 1.3, проверяет DER-сертификат сервера по pin и проверяет срок действия сертификата. Для плановой замены сертификата можно временно задать два pin; автоматического доверия новому сертификату нет. [Порядок ротации](GOST-IMPLEMENTATION.md#certificate-rotation-with-two-trusted-pins). На Android сокеты защищаются через `VpnService.protect` до TCP connect.

## Текущие релизы

- Ядро Linux: [1.12.2-igor.5](https://github.com/igor04091968/tiredvpn/releases/tag/v1.12.2-igor.5), архивы amd64/arm64 и контрольные суммы.
- Android: [1.12.1-igor.8](https://github.com/igor04091968/tiredvpn-android/releases/tag/v1.12.1-igor.8), versionCode 35; APK SHA-256 `36370e51165efed3d20437fd7cd2c85acfc807bc6ebf0814d2613e0803358117`.
- [F-Droid-репозиторий проекта](https://igor04091968.github.io/tiredvpn-fdroid/). Это отдельный репозиторий, его нужно добавить в F-Droid вручную; приложение не включено в каталог F-Droid.org.

[Настройка IPv6 (сервер и Android)](docs/ipv6-setup-ru.md) · [Состав релизов и проверки](docs/RELEASES-RU.md) · [Профиль ClientHello](docs/gost-cryptopro-clienthello.md) · [Предыдущая проверка на Tele2](docs/field-tests-tele2-2026-10-08.md) · [Результаты проверки ГОСТ с ноутбука](docs/GOST-IPERF-TEST-2026-10-12-RU.md). Результаты полевых проверок относятся к указанным там версиям и условиям сети.

## Материалы и компоненты

| Источник | Как использован |
| --- | --- |
| [TiredVPN](https://github.com/tiredvpn/tiredvpn) и [TiredVPN Android](https://github.com/tiredvpn/tiredvpn-android) | Исходный проект ядра и Android-клиента; изменения форка находятся в репозиториях `igor04091968`. |
| [gogost v3.0.0](https://gitverse.ru/uzer_007/gogost) | ГОСТ-криптография и TLS в ядре; локальная копия дополнена профилем ClientHello и тестами. Лицензии компонентов сохранены. |
| [CryptoPro CSP 5.0 R4](https://cryptopro.ru/products/csp/tls) | CSP 5.0.13820-7 и curl 8.21.0-CPRO использовали для собственных образцов TLS 1.3. CryptoPro не входит в APK и серверный бинарник. |
| [RFC 9367](https://www.rfc-editor.org/rfc/rfc9367.html) | Спецификация ГОСТ-криптонаборов TLS 1.3. |
| [Статья о сериях TLS-хэндшейков](https://habr.com/ru/articles/1044396/) | Материал для гипотезы, проверяемой в экспериментальной REALITY Single Flight; эффективность в конкретных сетях отдельно не доказана. |
| [DPI-CH](https://github.com/hyperion-cs/dpi-checkers/tree/main/ru/dpi-ch/docs) и [TSPU docs](https://github.com/DanielLavrushin/tspu-docs) | Справочные материалы при исследовании сетевой диагностики и фильтрации. |

Ядро форка собирается с Go 1.27.1. Android-клиент использует закреплённую версию ядра и собирается для `arm64-v8a`, `armeabi-v7a` и `x86_64`. Точные версии исходников и артефактов приведены в релизах.

---

## What is TiredVPN?

TiredVPN is a client-server VPN written in Go. It supports a set of transports and a strategy manager that can probe configured options and attempt alternatives when a connection attempt fails. The result depends on the selected strategy, server configuration, and network; the project does not claim that a transport defeats filtering in every network.

The fork's Linux release and Android release have separate version numbers and release workflows. Linux core release `1.12.2-igor.5` provides amd64 and arm64 archives. Android release `1.12.1-igor.8` (versionCode 35) contains the fork's native client libraries and is also available from the custom F-Droid repository linked above. Target VPS smoke-load measurements, rollout checks, and their limitations are recorded in [the release notes](docs/RELEASES-RU.md) and [GOST crypto-load report](docs/GOST-CRYPTO-LOAD.md).

## Features

- TCP/TLS, QUIC, REALITY, WebSocket, HTTP polling, and HTTP/2 transports, subject to configuration and server support.
- Experimental REALITY Single Flight variant with a global one-handshake limit and 450–600 ms spacing.
- Experimental strict GOST TLS 1.3 transport with explicit certificate pinning.
- SOCKS5 and HTTP proxy modes, and TUN mode where supported by the host.
- TOML configuration, endpoint pools, connection checks, and strategy selection.
- Optional traffic-shaping and packet-manipulation strategies.
- Linux amd64/arm64 release binaries; Android client libraries for arm64-v8a, armeabi-v7a, and x86_64.

The strategy list and defaults depend on flags and configuration. The GOST TLS handshake cap defaults to 128; this limits concurrent TLS negotiations, not established VPN sessions. The 2026-10-11 load report includes two comparison matrices for caps 128, 256, 512, 1024 and 4096. See [`tiredvpn client -help`](#building-from-source), [DPI strategy documentation](docs/strategies.md), and the [GOST load report](docs/GOST-CRYPTO-LOAD.md).

## Quick Start

### Download the fork's Linux binary

The fork publishes Linux archives on its [GitHub Releases page](https://github.com/igor04091968/tiredvpn/releases). For the current release on amd64:

```bash
VERSION=v1.12.2-igor.5
BASE="https://github.com/igor04091968/tiredvpn/releases/download/$VERSION"
curl -fLO "$BASE/tiredvpn-linux-amd64.tar.gz"
curl -fLO "$BASE/checksums.txt"
grep 'tiredvpn-linux-amd64.tar.gz' checksums.txt | sha256sum -c -
tar -xzf tiredvpn-linux-amd64.tar.gz
```

For arm64, use `tiredvpn-linux-arm64.tar.gz` and its line from `checksums.txt`. These are standalone binaries, not distro packages or preconfigured services. Read [Server Reference](docs/server.md) and [Deployment Guide](docs/deployment.md) before deploying a server.

### Build from source

```bash
git clone https://github.com/igor04091968/tiredvpn.git
cd tiredvpn
go build -o tiredvpn ./cmd/tiredvpn/
```

Run `./tiredvpn server -help` or `./tiredvpn client -help` to see options. The configuration examples are [`configs/client.example.toml`](configs/client.example.toml) and [`configs/server.example.toml`](configs/server.example.toml).

## Configuration

TiredVPN takes configuration from CLI flags, from a TOML file (`-config`), or
from both. Precedence is **CLI flag > TOML > default**, and a flag counts as
set only if it was passed explicitly - leaving it at its default value never
overwrites a TOML field.

```bash
tiredvpn client -config /etc/tiredvpn/client.toml
tiredvpn server -config /etc/tiredvpn/server.toml
```

Annotated examples: [`configs/client.example.toml`](configs/client.example.toml)
and [`configs/server.example.toml`](configs/server.example.toml). Unknown keys
are rejected, so a typo fails at startup instead of being ignored.

TOML does not yet cover the whole flag surface. On the client it carries the
server list, the selection policy, `strategy.mode`, `tls.fingerprint`, the
shaper and the log level; on the server, the listen address, the certificate
and key, and the log level. Everything else - `-secret`, the `-tun-*` flags,
the evasion knobs - is still flags only. The full mapping and the deprecation
plan are in
[`internal/config/toml/MIGRATION.md`](internal/config/toml/MIGRATION.md).

Run `tiredvpn server -help` or `tiredvpn client -help` for the full flag list.

### Server flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | | Path to a TOML config; CLI flags override it |
| `-listen` | `:443` | IPv4 listen address |
| `-listen-v6` | | IPv6 listen address (default: `[::]` on the `-listen` port) |
| `-dual-stack` | `true` | Listen on both IPv4 and IPv6 |
| `-cert` | `server.crt` | TLS certificate file |
| `-key` | `server.key` | TLS private key file |
| `-secret` | | Shared secret (single-client mode) |
| `-redis` | | Redis address for multi-client mode |
| `-redis-db` | `0` | Redis logical database, 0-15 (`TIREDVPN_REDIS_DB`) |
| `-redis-prefix` | `tiredvpn:` | Redis key namespace (`TIREDVPN_REDIS_PREFIX`) |
| `-api-addr` | `127.0.0.1:8080` | REST API for client management |
| `-api-token` | | Bearer token for the management API (`TIREDVPN_API_TOKEN`) |
| `-ip-pool` | | CIDR for TUN client IP assignment |
| `-ip-pool-v6` | | IPv6 ULA prefix for dual-stack TUN clients |
| `-tun-mtu` | `1280` | TUN interface MTU (1280-9000) |
| `-port-range` | | Multi-port listening (e.g. `47000-47100`) |
| `-no-quic` | `false` | Disable QUIC/UDP listener |
| `-upstream` | | Upstream server for multi-hop |
| `-fake-root` | `./www` | Directory served to unauthenticated visitors |
| `-enable-icmp` | `false` | Enable ICMP tunnel listener (requires CAP_NET_RAW) |
| `-reality-b1` | `false` | Accept the REALITY B1 transport; needs `-reality-private-key` |
| `-reality-private-key` | | Static X25519 key, base64 (`TIREDVPN_REALITY_PRIVATE_KEY`) |
| `-max-conns` | `0` | Cap on in-flight incoming connections (0 = 4096 for exit mode, 256 for relay mode) |
| `-gost-listen` | disabled | Separate experimental GOST TLS 1.3 TCP listener; requires `-gost-cert` and `-gost-key` |
| `-gost-cert` | | PEM GOST certificate; enables the experimental listener when paired with the other GOST server options |
| `-gost-key` | | PKCS #8 PEM private key matching `-gost-cert` |
| `-gost-max-handshakes` | `0` (128) | Concurrent GOST TLS negotiations; the slot is released after TLS succeeds or fails. Does not cap established sessions. |
| `-pprof` | | Serve pprof on this address (e.g. `:6060`) |
| `-debug` | `false` | Verbose logging |

Generate the B1 key pair with `tiredvpn reality-keygen`.

### Client flags

These are core CLI options; Android exposes only the options wired through its UI and service and does not pass `-port-hop`. Status caveats: `-pq` and `-pq-server-key` currently do not perform a post-quantum key exchange; ECH is limited to the stego and anti-probe strategies and needs an out-of-band `-ech-config`; the `-fallback` flag is parsed but does not control mid-session fallback. See [security limitations](docs/security.md#known-limitations), [ECH details](docs/security.md#encrypted-client-hello), and [strategy behavior](docs/strategies.md#mid-session-fallback).

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | | Path to a TOML config; CLI flags override it |
| `-server` | | Remote server address (required unless the config lists servers) |
| `-server-v6` | | Same server over IPv6 (e.g. `[2001:db8::1]:995`) |
| `-server-policy` | | Order of the `[[servers]]` list: `priority`, `latency`, `weighted` (empty = `priority`) |
| `-secret` | | Shared secret (required) |
| `-listen` | `127.0.0.1:1080` | Local SOCKS5/HTTP proxy address |
| `-http-listen` | | Separate HTTP proxy address |
| `-tun` | `false` | Enable TUN mode (full VPN) |
| `-tun-routes` | | Routes to tunnel (e.g. `0.0.0.0/0`) |
| `-tun-ipv6` | `dual` | IPv6 while the tunnel is up: `dual`, `block`, `off` |
| `-tun-ipv6-allow` | | Exceptions to the IPv6 block: interface names and/or prefixes, comma-separated |
| `-tun-routes6` | | IPv6 destinations the tunnel claims; `none` leaves the host's own IPv6 routing alone |
| `-tun-mtu` | `1280` | TUN MTU; with `-auto-mtu` this is the upper bound |
| `-auto-mtu` | `true` | Probe the real end-to-end MTU and apply `min(probed, -tun-mtu)` |
| `-quic` | `false` | Enable QUIC transport |
| `-strategy` | | Force a specific strategy (`-list` prints them) |
| `-seqovl-packet` | `false` | Packet-level TCP sequence overlap for `seqovl` (Linux + CAP_NET_ADMIN) |
| `-port-hop` | `false` | Enable port hopping |
| `-ech` | `false` | ECH for stego/anti-probe only; requires an out-of-band `-ech-config` |
| `-pq` | `false` | Reserved/inert: currently performs no post-quantum key exchange |
| `-rtt-masking` | `false` | Hide proxy timing signature |
| `-shaper` | | Traffic shaper preset for the morph strategies |
| `-prefer-ipv6` | `true` | Prefer IPv6 transport |
| `-fallback-v4` | `true` | Fall back to IPv4 if IPv6 fails |
| `-fallback` | `true` | Parsed, but currently does not control mid-session strategy fallback |
| `-benchmark` | `false` | Run strategy latency benchmark |
| `-debug` | `false` | Verbose logging |

### Several servers

A list of servers is config-file only - there is no flag that takes more than
one address. `[server]` and `[[servers]]` are mutually exclusive (a lone
`[server]` *is* a one-element list), and passing `-server` collapses whatever
the file says to a single entry.

```toml
[[servers]]
name = "ams"
address = "203.0.113.10"
port = 443
address_v6 = "2001:db8::10"
weight = 100

[[servers]]
name = "fra"
address = "203.0.113.20"
port = 443
weight = 50

[selection]
policy = "priority"      # priority (list order) | latency | weighted
family = "prefer_v6"     # prefer_v6 | prefer_v4 | v6_only | v4_only
failure_threshold = 2    # failed connect cycles before a candidate is parked
cooldown = "1m"          # first cooldown; doubles per repeat, jittered
max_cooldown = "30m"
min_dwell = "5m"         # hold a fallback this long before going back
health_check = "off"     # off | active
```

A dial target is an (endpoint, family) pair, so moving from IPv6 to IPv4 and
moving between servers are the same operation. Background health checking is
off by default on purpose: polling every server on a timer is a periodic
fan-out pattern with nothing behind it. With it off, the client learns a server
is up by dialling it.

### Client management

```bash
# Add a client (multi-client mode with Redis); -name is required
tiredvpn admin add -api http://127.0.0.1:8080 -server vpn.example.com:443 -name alice

# List clients
tiredvpn admin list -api http://127.0.0.1:8080

# Delete a client
tiredvpn admin delete -api http://127.0.0.1:8080 -id <client-id>

# Generate QR code for mobile app
tiredvpn admin qr -server vpn.example.com:443 -secret <secret>
```

If the server runs with `-api-token`, pass the same value as `-api-token` to
the `add`, `list`, and `delete` subcommands (or set `TIREDVPN_API_TOKEN`).

---

## Docker and Helm

The fork's release workflow does not publish images to the upstream `tiredvpn/tiredvpn` Docker Hub namespace. The upstream image and the upstream `docker-compose.yml` do not include these fork releases. The repository contains a Dockerfile and Helm chart for local builds/deployment; use the files from this fork's checkout and pin the image/chart you build yourself.

## Building from Source

### Requirements

- Go 1.27.1 (the version used by the current release workflow)
- Linux, macOS, or Windows; TUN operation depends on OS support and privileges

### Build and test

```bash
git clone https://github.com/igor04091968/tiredvpn.git
cd tiredvpn
go build -o tiredvpn ./cmd/tiredvpn/
go vet ./...
go test -race -timeout 5m -short ./internal/...
```

The release workflow also runs the GOST ClientHello regression tests and lint before publishing release binaries.

## Strategies

The manager can probe and rank registered strategies and try another option
when a connection attempt fails. This does not guarantee a working route through
a filtered network. `tiredvpn client -list` prints registered strategies;
`-strategy <id>` selects one explicitly.

| ID | Name | Description |
|----|------|-------------|
| `reality` | REALITY Protocol | REALITY transport; behavior depends on configured server and TLS fingerprint. |
| `reality_singleflight` | REALITY Single Flight | Experimental REALITY variant; one concurrent handshake globally, with 450–600 ms spacing. |
| [ГОСТ transport](GOST-IMPLEMENTATION.md) | ГОСТ TLS 1.3 | Experimental transport with explicit certificate pinning and controlled compatibility checks. |
| `quic_salamander` | QUIC Salamander | QUIC over UDP with Salamander padding (opt-in: `-quic`) |
| `quic` | QUIC Tunnel | QUIC transport (opt-in: `-quic`); compatibility and filtering results depend on the network |
| `seqovl` | Seqovl (Sequence Overlap) | Experimental packet-level sequence overlap; packet-level mode requires Linux and `CAP_NET_ADMIN` |
| `http2_stego` | HTTP/2 Steganography | HTTP/2 transport with padding; requires compatible server and client settings |
| `websocket_padded` | WebSocket Salamander | WebSocket transport with Salamander obfuscation padding |
| `http_polling` | HTTP Polling | Short-lived HTTP/1.1 requests (meek-style); requires compatible server and client settings |
| `morph_*` | Traffic Morphing | Reshapes traffic to match video streaming profiles (Yandex, VK, Baidu, Aparat) |
| `confusion_*` | Protocol Confusion | Makes packets appear as DNS/HTTP/SSH/SMTP over TLS, plus a multi-layer variant |
| `geneva_*` | Geneva Engine | Packet-manipulation strategies registered for Russia, China, and Iran. |
| `antiprobe` | Anti-Probe | Server-side probe resistance; behavior depends on server configuration |
| `state_exhaustion` | State Exhaustion | Experimental strategy that generates decoy traffic. Its effect depends on the network. |
| `mesh_relay` | Mesh Relay | Routes through relay nodes in regions with lighter filtering (opt-in, needs relay nodes configured) |
| `icmp_tunnel` | ICMP Tunnel | Backup tunnel over ICMP Echo (opt-in: `-icmp-tunnel`, requires CAP_NET_RAW and a server started with `-enable-icmp`) |
| `ssh_camouflage` | SSH Camouflage | Tunnel under SSH traffic (priority 28, requires server support) |
| `imap_camouflage` | IMAP Camouflage | Tunnel under IMAP mail protocol (priority 29, requires server support) |

The strategy manager provides:

- **Automatic probing** - tests all available strategies and ranks by latency
- **Circuit breakers** - disables failing strategies after configurable threshold
- **Connection-attempt fallback** - tries another configured option after a failed connection attempt; this does not promise a seamless mid-session protocol switch
- **Re-probing** - re-evaluates strategies according to the configured connection flow
- **Benchmarking** - `tiredvpn client -benchmark` to test all strategies

---

## Architecture

```
cmd/tiredvpn/          CLI entrypoint (server, client, admin, reality-keygen)
internal/
  server/              Server-side connection handling, TLS/QUIC listeners
  client/              Client-side proxy, TUN, strategy orchestration
  strategy/            DPI bypass strategies and adaptive engine
  endpoint/            Server pool: candidates, selection policy, parking
  tun/                 TUN device management, routes, IPv6 policy
  mux/                 smux multiplexer integration
  protocol/            Wire format and handshake versions
  tls/                 TLS utilities and uTLS fingerprinting
  evasion/             Low-level evasion primitives
  geneva/              Geneva packet manipulation engine
  detect/              Network and blocking detection
  porthopping/         Port hopping logic
  pool/                IP address pool for TUN clients
  shaper/              Behavioural traffic shaping (presets, distributions)
  metrics/             Prometheus metrics collector
  padding/             Traffic padding utilities
  protect/             Android VpnService socket protection
  control/             Android control socket protocol
  capabilities/        Runtime capability probing
  config/toml/         TOML schema, loader, and CLI-override resolver
  log/                 Structured logging
  benchmark/           Strategy benchmarking
  buildinfo/           Version and build metadata
  integration/         Cross-package integration tests
  ktls/                Kernel TLS offload
```

---

## Documentation

Full documentation is available in the [docs/](docs/) directory:

- [Getting Started](docs/getting-started.md)
- [Server Reference](docs/server.md)
- [Client Reference](docs/client.md)
- [Admin and Client Management](docs/admin.md)
- [DPI Bypass Strategies](docs/strategies.md)
- [Architecture](docs/architecture.md)
- [Deployment Guide](docs/deployment.md)
- [Security Model](docs/security.md)
- [Monitoring](docs/monitoring.md)

---

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines on submitting patches, reporting issues, and the development
workflow.

Before submitting a pull request:

1. Run `make test` and ensure all tests pass
2. Run `make lint` if you have golangci-lint installed
3. Keep commits focused and well-described

---

## Community

- [GitHub Discussions](https://github.com/igor04091968/tiredvpn/issues) — bugs and feature requests

---

## Авторство собственного форка

Инициатор концепции развития форка с транспортом ГОСТ — Igor Rachkov (`igor04091968`). [Уведомление об авторстве и границах прав](AUTHORSHIP.md). Права исходного TiredVPN и сторонних компонентов сохранены.

## License

TiredVPN is licensed under the [GNU Affero General Public License v3.0](LICENSE).
