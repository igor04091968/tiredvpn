# gogost

`gogost` — Go-библиотека ГОСТ-алгоритмов с упором на практическое применение,
низкие задержки и предсказуемый API. Пакет развивается как самостоятельный
форк с модулем `gitverse.ru/uzer_007/gogost/v3`.

Путь модуля v3 — `gitverse.ru/uzer_007/gogost/v3`. Для обновления с v2
смотрите [руководство по миграции](docs/migration-v3.md) и
[историю изменений](CHANGELOG.md).

## Установка v3.0.0

Подключите опубликованный модуль:

```bash
go get gitverse.ru/uzer_007/gogost/v3@v3.0.0
```

Для разработки с локальным checkout используйте `replace`:

```bash
go mod edit -require=gitverse.ru/uzer_007/gogost/v3@v3.0.0
go mod edit -replace=gitverse.ru/uzer_007/gogost/v3=../gogost
go mod tidy
```

`../gogost` замените путём к этому checkout. Требуется Go 1.27.1 или новее.
Импорты используют суффикс `/v3`:

```go
import "gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
```

## Документация

- [Карта документации](docs/index.md)
- [Быстрый старт](docs/quick-start.md)
- [ГОСТ TLS для TCP и net/http](docs/gost-tls.md)
- [Сертификаты X.509 ГОСТ](docs/x509.md)
- [CMS: подписи, шифрование и метки времени](docs/cms.md)
- [Контейнеры PFX и зашифрованные ключи](docs/pfx.md)
- [Экспериментальная подпись «Шиповник»](shipovnik/README.md)
- [Алгоритмы и пакеты](docs/algorithms.md)
- [Режимы ГОСТ 34.13](docs/modes.md)
- [Как выбрать режим](docs/mode-selection.md)
- [Пароли и KDF](docs/passwords-and-kdf.md)
- [Производительность](docs/performance.md)
- [Безопасность](docs/security.md)
- [Миграция на v2.5.0](docs/migration-v2.5.0.md)
- [Миграция на v3](docs/migration-v3.md)

## Возможности

| Пакет | Назначение |
| --- | --- |
| `gost28147` | ГОСТ 28147-89, S-box, CTR/MAC и fast helpers |
| `gost341264` | Магма, ГОСТ Р 34.12-2015 |
| `gost3412128` | Кузнечик, ГОСТ Р 34.12-2015 |
| `gost3413/modes` | Рекомендуемый high-level API для ECB/CBC/CFB/OFB/CTR/CTR-ACPKM/MAC/MGM |
| `gost34112012256` | Стрибог-256, KDF, TLS tree, ESP tree, GOST yescrypt |
| `gost34112012512` | Стрибог-512 и GOST yescrypt |
| `gost341194` | ГОСТ Р 34.11-94 |
| `gost3410` | ГОСТ Р 34.10-2001/2012: ключи, подпись, проверка, VKO |
| `shipovnik` | Экспериментальная постквантовая подпись «Шиповник» |
| `gosttls` | Подключаемый ГОСТ TLS 1.3 по RFC 9367 без замены Go SDK |
| `gostx509` | X.509, CSR, CRL, PKIX, PKCS #8 и парольные PFX для ГОСТ |
| `gosthttp` | HTTP/1.1, HTTP/2, HTTP/HTTPS CONNECT и SOCKS5-прокси поверх ГОСТ TLS |
| `mgm` | MGM AEAD для 64- и 128-битных блочных шифров |
| `keywrap` | Обёртка ключей для ГОСТ 28147-89, Магмы и Кузнечика |
| `cms` | Стандартные CMS SignedData и EnvelopedData с ГОСТ, RFC 3161 и CAdES-T |
| `pfx` | Транспортные контейнеры PFX с паролем или защитой получателей по открытому ключу |
| `profiles` | Готовые presets для типовых сценариев |
| `prfplus` | PRF+ для IPsec/IKE на базе Стрибога |

## ГОСТ TLS без замены Go SDK

```go
config := gosttls.GOSTConfig(&gosttls.Config{
    RootCAs:    roots,
    ServerName: "server.example",
})

// TCP: *gosttls.Conn реализует net.Conn.
conn, err := gosttls.Dial("tcp", "server.example:8443", config)

// HTTP/1.1 или HTTP/2 выбирается по ALPN автоматически.
client := gosthttp.NewClient(config)
response, err := client.Get("https://server.example:8443/")
```

Реализация подключается как обычные пакеты модуля и не требует патчить `GOROOT`
или переустанавливать Go. `gosthttp.NewTransport` поддерживает HTTP/HTTPS
forward proxy через CONNECT и `socks5`/`socks5h`, включая Basic/custom auth,
RFC 1929 username/password и `gosthttp.ProxyFromEnvironment` с `ALL_PROXY`.
Серверные примеры, загрузка сертификатов и ограничения описаны в
[руководстве по ГОСТ TLS](docs/gost-tls.md).

QUIC намеренно не входит в этот пакет: он будет реализован позже отдельным
пакетом `gostquic`.

## Быстрый пример: high-level CBC

```go
package main

import (
"bytes"
"fmt"

"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

func main() {
key := []byte("0123456789abcdef0123456789abcdef")
iv := []byte("1234567890abcdef")
plaintext := []byte("message")

engine := modes.MustKuznechik(key)
cbc, err := engine.CBC(iv, modes.PaddingDefault)
if err != nil {
    panic(err)
}

ciphertext, err := cbc.Encrypt(nil, plaintext)
if err != nil {
    panic(err)
}
decrypted, err := cbc.Decrypt(nil, ciphertext)
if err != nil {
    panic(err)
}
fmt.Println(bytes.Equal(decrypted, plaintext))
}
```

## Быстрый пример: Стрибог-256

```go
package main

import (
 "fmt"

 "gitverse.ru/uzer_007/gogost/v3/gost34112012256"
)

func main() {
 h := gost34112012256.New()
 _, _ = h.Write([]byte("message"))
 fmt.Printf("%x\n", h.Sum(nil))
}
```

## Производительность

Горячие пути оптимизированы для повторного использования prepared objects:

- `gost3413/modes` кэширует concrete hooks и поддерживает параллельные режимы
  там, где это допускает ГОСТ 34.13.
- `gost3412128` использует asm/AVX2 bulk helpers на amd64 и pure Go fallback.
- `gost28147` и `gost341264` используют быстрые LUT/T16 и AVX2-пути для
  bulk/CTR; у Магмы зависимые блоки и MAC ускоряются компактным скалярным
  asm-путём на amd64.
- `gost3410` использует fixed-limb `[4]uint64`/`[8]uint64` backend для всех
  встроенных кривых 2001/2012, Montgomery-арифметику, mixed Edwards fixed-base
  comb, ADX/BMI2 leaf primitives на amd64, `MUL`/`UMULH`/`ADCS` на arm64 и
  специализированную редукцию поля `2²⁵⁶ - 617`.
- `gosttls` использует конкретный HMAC/HKDF Стрибог без `hash.Hash` и
  переиспользует TLSTREE/cipher/MGM при смене traffic secret; `gosthttp` избегает
  waiter/timer allocations на прогретом неконкурентном пути.

Запуск benchmark:

```bash
go test -benchmem -bench . ./...
```

Для переносимой сборки без asm:

```bash
go test -tags purego ./...
```

## Безопасность

Библиотека предоставляет криптографические примитивы и удобные helper API, но
не заменяет проектирование протокола, управление ключами и сертифицированный
криптопровайдер там, где он требуется. Для новых протоколов предпочитайте
authenticated encryption, например MGM через `gost3413/modes`.

Подробнее: [docs/security.md](docs/security.md).

## Лицензия и авторство

Проект распространяется по лицензии MIT. См. `LICENSE`, `AUTHORS` и историю
коммитов проекта.
