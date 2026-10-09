# Миграция на v2.5.0

Версия `v2.5.0` закрепляет библиотеку как самостоятельный production-пакет:
добавлены подготовленные high-level режимы, ГОСТ 28147-89 в `gost3413/modes`,
параллельная обработка и новые fast paths.

## Module path

Используйте v2 module path:

```go
import "gitverse.ru/uzer_007/gogost/v2/gost3413/modes"
```

Установка:

```bash
go get gitverse.ru/uzer_007/gogost/v2@v2.5.0
```

## Переход на prepared modes

До v2.5.0 типичный код часто создавал block cipher и режим рядом с каждой
операцией. Фрагменты ниже предполагают уже подготовленные `key`, `iv`, `src` и
`dst`. Новый рекомендуемый путь:

```go
engine := modes.MustKuznechik(key)
ctr, err := engine.CTR(iv)
if err != nil {
	panic(err)
}
_, err = ctr.XORKeyStreamTo(dst, src)
```

Преимущества:

- расписание ключей строится один раз;
- режим хранит IV template и scratch buffers;
- доступны `*To` методы без append-роста;
- крупные параллелимые режимы могут использовать automatic/manual workers.

## ГОСТ 28147-89 в modes

Для совместимых протоколов теперь можно использовать ГОСТ 28147-89 через тот же
high-level API. Фрагменты предполагают 256-битный `key` и IV нужного размера:

```go
engine := modes.MustGOST28147Default(key)
cbc, err := engine.CBC(iv, modes.PaddingDefault)
```

Если нужен конкретный S-box:

```go
engine := modes.MustGOST28147(key, gost28147.SboxDefault)
```

## Worker API

Для крупных буферов:

```go
ctr, _ := engine.CTR(iv)
_ = ctr.SetWorkers(4)
defer ctr.Close()
```

`WithWorkers` полезен для разового ручного вызова. `SetWorkers` полезен для
повторных операций, потому worker pool переиспользуется.

## Тексты ошибок

В v2.5.0 пользовательские тексты ошибок переведены на русский язык. Если код
обрабатывает sentinel errors, не сравнивайте строку `err.Error()`: используйте
`errors.Is` и публичные переменные ошибок пакетов.

## Кузнечик и старый API

Используйте `gost3412128.Cipher` и `gost3412128.NewCipher`. Старые
исследовательские псевдонимы и backend-кандидаты не являются частью production
API.
