# `shipovnik`

Пакет реализует экспериментальную постквантовую подпись «Шиповник» в формате
эталона QAPP. Он не изменяет и не зависит от `gosttls`, `gostx509` и `gosthttp`.

Источники: [публикация ТГУ](https://journals.tsu.ru/engine/download.php?id=244232&area=files),
[QAPP-tech/shipovnik_tc26](https://github.com/QAPP-tech/shipovnik_tc26).

Поддерживаются только фиксированные профили:

| Профиль | δ | Минимальная подпись | Максимальная подпись |
|---|---:|---:|---:|
| `Reference()` | 219 | 200 604 байта | 1 072 662 байта |
| `Article70()` | 137 | 125 492 байта | 671 026 байт |

`Article70()` — историко-исследовательский 70-битный пример из публикации. Его
нельзя выбирать как неявный downgrade. Raw-ключ не содержит идентификатор
профиля: один и тот же raw-ключ нельзя повторно импортировать в разные схемы.

```go
scheme := shipovnik.Reference()
privateKey, err := scheme.GenerateKey(rand.Reader)
if err != nil {
    return err
}

signature, err := privateKey.SignMessage(rand.Reader, message, nil)
if err != nil {
    return err
}
publicKey := privateKey.Public().(*shipovnik.PublicKey)
valid, err := publicKey.Verify(message, signature, nil)
```

`Options{Workers: 0}` выбирает число workers автоматически, `1` включает
последовательный режим, значение больше `1` задаёт явный предел. Чтение entropy
всегда остаётся последовательным, поэтому при одинаковом потоке entropy число
workers не меняет подпись. Для длительных операций доступны варианты с
`context.Context`.

`PrivateKey` реализует `crypto.Signer`, однако его аргумент `digest` трактуется
как исходное сообщение. Разрешён только `SignerOpts.HashFunc() == 0`.

Ошибки структурного кодирования распознаются через `ErrInvalidSignature`.
Структурно корректная подпись с неверными commitments возвращает `(false, nil)`.

## Совместимость и матрица

`h_prime.bin` воспроизводится командой:

```text
go run ./shipovnik/internal/cmd/genmatrix -output shipovnik/h_prime.bin
```

Генератор загружает `src/h_prime.c` из закреплённого коммита
`a9139ef6178a6dfebac3ae328817a361f0e85256`, извлекает построчную матрицу и
проверяет SHA-256. Лицензия и provenance приведены в `NOTICE`.

Обычные проверки:

```text
go test ./shipovnik
go test -tags purego ./shipovnik
```

## Выбор CPU backend

На `amd64` пакет один раз при инициализации выбирает наиболее быстрый
доступный backend синдрома: AVX2+POPCNT, SSE2+POPCNT либо базовый SSE2 без
опциональных расширений. `POPCNT` проверяется отдельно: наличие SSE4.2 само по
себе его не гарантирует. Сборки с тегом `purego`, 32-битный x86 и остальные
архитектуры используют переносимую Go-реализацию.

Чтобы один amd64-бинарник запускался как на AVX2, так и на старых процессорах,
его следует собирать с базовым уровнем ISA:

```text
GOAMD64=v1 go build ./...
```

На PowerShell эквивалентная настройка задаётся как `$env:GOAMD64 = "v1"`.
`GOAMD64=v3` разрешает компилятору использовать AVX2 во всём бинарнике и потому
не подходит для распространения на оборудование без AVX2, независимо от
runtime-dispatch внутри `shipovnik`.

Opt-in тест `go test -tags cinterop ./shipovnik -run TestQAPPCrossVerify`
проверяет оба направления Go ↔ C. Он ожидает пути к helper-сборкам из
`testdata/qapp_interop.c` в переменных `SHIPOVNIK_QAPP_REFERENCE` (`δ=219`) и
`SHIPOVNIK_QAPP_ARTICLE70` (`δ=137`).

Helper линкуется с неизменёнными `shipovnik`/`streebog` QAPP и заменяет только
тестовый поток entropy и медленную сортировочную сеть генерации перестановок:

```text
gcc -O2 -I<QAPP>/include/shipovnik -I<QAPP>/src \
  shipovnik/testdata/qapp_interop.c \
  <QAPP-BUILD>/libshipovnik.a <QAPP-BUILD>/streebog/libstreebog.a \
  -o qapp_interop
```

Для `Article70` перед сборкой отдельной копии QAPP в `params.h` меняется только
`DELTA` с `219` на `137`. `testdata/qapp_benchmark.c` предназначен для сравнения
с полностью неизменённым upstream signer, включая его sorting network.
