# Быстрый старт

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

`../gogost` — путь к локальному checkout.
Все импорты текущего исходного дерева используют суффикс `/v3`:

```go
import "gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
```

Требуется Go 1.27.1 или новее.

## Стрибог-256

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

## Кузнечик как `cipher.Block`

```go
package main

import (
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost3412128"
)

func main() {
	key := make([]byte, gost3412128.KeySize)
	block := gost3412128.NewCipher(key)

	src := make([]byte, gost3412128.BlockSize)
	dst := make([]byte, gost3412128.BlockSize)
	block.Encrypt(dst, src)
	fmt.Printf("%x\n", dst)
}
```

## High-level режим CBC

`gost3413/modes` создаёт объект алгоритма один раз, а затем переиспользует
подготовленные режимы без повторного построения расписания ключей.

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

## MGM AEAD

```go
package main

import (
	"bytes"
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost3413/modes"
)

func main() {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := []byte("1234567890abcdef")

	engine := modes.MustKuznechik(key)
	aead, err := engine.MGM(16)
	if err != nil {
		panic(err)
	}

	sealed, err := aead.Seal(nil, nonce, []byte("message"), []byte("metadata"))
	if err != nil {
		panic(err)
	}
	opened, err := aead.Open(nil, nonce, sealed, []byte("metadata"))
	if err != nil {
		panic(err)
	}
	fmt.Println(bytes.Equal(opened, []byte("message")))
}
```

## Проверка установки

```bash
go test ./...
go test -run Example ./...
```
