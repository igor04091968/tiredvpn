# Режимы ГОСТ 34.13

Пакет `gost3413/modes` — основной high-level API библиотеки для шифрования
данных. Пользователь создаёт объект алгоритма один раз, затем создаёт
подготовленный режим и переиспользует его для многих операций.

Короткие Go-блоки ниже являются фрагментами: они предполагают, что нужные
переменные (`key`, `iv`, `src`, `dst`, `plaintext`, `data`, `nonce`, `ad`) уже
созданы в вызывающем коде. Полные копируемые программы приведены в
[`quick-start.md`](quick-start.md).

Если нужно выбрать режим для нового протокола, начните с
[`mode-selection.md`](mode-selection.md): там разобраны плюсы, минусы и типичные
ошибки ECB/CBC/CFB/OFB/CTR/CTR-ACPKM/MAC/MGM.

## Алгоритмы

```go
engine := modes.MustKuznechik(key)
engine := modes.MustMagma(key)
engine := modes.MustGOST28147Default(key)
engine := modes.MustGOST28147(key, gost28147.SboxDefault)
```

Конструкторы `New*` возвращают ошибку, `Must*` паникуют при неверном ключе или
S-box. Для нового кода удобнее начинать с `New*`, а `Must*` оставлять для
статически заданных тестовых ключей и примеров.

## Padding

ECB и CBC работают с padding:

- `PaddingDefault` соответствует `Padding2`;
- `PaddingNone` требует block-aligned input;
- `Padding1`, `Padding2`, `Padding3` доступны явно.

Потоковые режимы CFB/OFB/CTR/CTR-ACPKM padding не используют.

## IV и nonce

- CBC: IV равен размеру блока.
- CFB/OFB: IV равен размеру регистра; в обычном варианте это размер блока.
- CTR и CTR-ACPKM: IV может быть половиной блока или полным counter block.
- MGM: nonce равен размеру блока и не должен иметь установленный старший бит.

Повторное использование IV/nonce с одним ключом может нарушить безопасность
режима. Для потоковых режимов и MGM используйте уникальные значения.

## Методы `*To`

Append-методы удобны:

```go
ciphertext, err := ctr.XORKeyStream(nil, plaintext)
```

Для минимальной задержки и контроля выделений используйте `*To`:

```go
dst := make([]byte, len(plaintext))
_, err := ctr.XORKeyStreamTo(dst, plaintext)
```

`*To` требует заранее выделенный `dst` нужного размера и возвращает ошибку, если
буфер слишком мал или перекрытие входа/выхода небезопасно.

## Параллельная обработка

Автоматический режим включается только на крупных входах и только там, где режим
допускает независимую обработку блоков:

- ECB encrypt/decrypt;
- CBC decrypt;
- CFB decrypt при полном сегменте;
- CTR;
- CTR-ACPKM.

Ручное управление доступно через `WithWorkers` и `SetWorkers`:

```go
ctr, _ := engine.CTR(iv)
_ = ctr.SetWorkers(4)
defer ctr.Close()

_, err := ctr.XORKeyStreamTo(dst, src)
```

`SetWorkers` создаёт постоянный worker pool внутри prepared object. `ResetWorkers`
возвращает автоматическую политику, `Close` освобождает pool. Значение
`workers <= 1` считается ошибкой: для последовательного выполнения используйте
обычные методы.

Mode objects не предназначены для одновременного вызова из нескольких внешних
goroutine. Для параллельной обработки на уровне приложения создавайте отдельный
prepared object на worker.

## CTR-ACPKM

CTR-ACPKM переинициализирует ключ по секциям. Чтобы убрать задержку первого
вызова, заранее прогрейте кэш секций:

```go
stream, _ := engine.CTRACPKM(iv, modes.DefaultACPKMSectionSize)
_ = stream.PrecomputeSections(len(src))
_, err := stream.XORKeyStreamTo(dst, src)
```

## MAC и MGM

MAC возвращает tag заданного размера:

```go
mac, _ := engine.MAC(8)
tag := mac.Sum(nil, data)
ok := mac.Verify(data, tag)
```

MGM добавляет authentication tag и проверяет associated data:

```go
aead, _ := engine.MGM(16)
sealed, err := aead.Seal(nil, nonce, plaintext, ad)
opened, err := aead.Open(nil, nonce, sealed, ad)
```

При ошибке проверки tag данные не должны использоваться.
