# Пароли и KDF

Эта страница помогает выбрать способ работы с паролями и ключевым материалом.
Главное правило: пароль пользователя и криптографический ключ — разные сущности.
Пароль нужно замедлять и солить, а ключи для режимов шифрования должны иметь
точный размер алгоритма.

## Быстрый выбор

| Задача | Что использовать |
| --- | --- |
| Хранение пользовательских паролей | GOST yescrypt |
| Получение ключа из парольной фразы для совместимых контейнеров | PBKDF2 со Стрибогом |
| Разделение уже случайного мастер-ключа по назначениям | `gost34112012256.NewKDF` |
| Деривация ключей по TLS sequence number | `TLSTree` |
| Деривация ключей ESP/IPsec | `ESPTree` или `prfplus` |

`nil` salt допустим только как совместимый fallback в helper API. В реальных
парольных сценариях всегда генерируйте случайную соль и храните её рядом с
хешем или зашифрованным контейнером.

## GOST yescrypt для хранения паролей

GOST yescrypt — рекомендуемый путь для password storage в этой библиотеке. Он
использует yescrypt как memory-hard основу и Стрибог/HMAC-обвязку. Такой хеш
нужен для проверки пароля пользователя после утечки базы: атакующий должен
тратить заметные CPU/RAM ресурсы на каждую догадку.

```go
package main

import (
	"crypto/rand"
	"fmt"
	"strings"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
)

func main() {
	password := []byte("correct horse battery staple")
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	hash, err := gost34112012256.GostYescrypt(salt, password)
	if err != nil {
		panic(err)
	}
	record := gost34112012256.FormatGostYescryptHash(salt, hash)

	ok, err := gost34112012256.VerifyGostYescryptHash(record, password)
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.HasPrefix(record, "$gy$"), ok)
}
```

Практические правила:

- соль должна быть случайной и уникальной для каждого пароля;
- форматированный хеш проверяйте через `VerifyGostYescryptHash`;
- неверный пароль возвращает `false, nil`, а повреждённая или неподдерживаемая
  строка хеша — `false, error`;
- для новых записей предпочитайте 256-битный helper; 512-битный вариант полезен,
  если этого требует профиль совместимости;
- не используйте обычный Стрибог без KDF для хранения паролей: быстрый хеш
  слишком удобен для offline-перебора.

## PBKDF2 со Стрибогом для ключа из парольной фразы

PBKDF2 полезен, когда нужен совместимый password-based key derivation: например,
получить 32-байтный ключ Магмы/Кузнечика из парольной фразы. В Go используется
стандартный пакет `crypto/pbkdf2`, а Стрибог передаётся как HMAC hash factory.

```go
package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012512"
)

func main() {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}

	key, err := pbkdf2.Key(
		gost34112012512.New,
		"password phrase",
		salt,
		200_000,
		32,
	)
	if err != nil {
		panic(err)
	}

	fmt.Println(len(key))
}
```

Количество итераций подбирайте под целевую задержку на вашей инфраструктуре.
Для интерактивного входа обычно выбирают задержку, заметную для атакующего, но
приемлемую для пользователя; для фоновой расшифровки контейнера можно позволить
более дорогой derivation. Соль хранится рядом с ciphertext и не является
секретом.

PBKDF2 не является лучшим выбором для хранения паролей в новой базе: он не
memory-hard. Для password storage используйте GOST yescrypt, а PBKDF2 оставляйте
для совместимости и получения ключей из парольной фразы.

## ГОСТ KDF для разделения ключей

`gost34112012256.NewKDF` предназначен не для пароля, а для уже стойкого
ключевого материала: например, когда из мастер-ключа нужно получить отдельные
ключи для шифрования и MAC.

```go
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"gitverse.ru/uzer_007/gogost/v3/gost34112012256"
)

func main() {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		panic(err)
	}

	kdf := gost34112012256.NewKDF(master)
	encryptionKey := kdf.DeriveInto(nil, []byte("encryption"), []byte("file:42"))
	macKey := kdf.DeriveInto(nil, []byte("mac"), []byte("file:42"))

	fmt.Println(len(encryptionKey), len(macKey), bytes.Equal(encryptionKey, macKey))
}
```

Используйте разные `label` для разных назначений и стабильный `seed` для
контекста: идентификатор протокола, номер контейнера, версию ключа или похожий
домен разделения.

## TLS tree, ESP tree и PRF+

`TLSTree`, `ESPTree` и `prfplus` нужны для протокольных схем, где способ
получения дочерних ключей уже задан профилем:

- `TLSTree` производит ключи по sequence number и параметрам TLS-профиля;
- `ESPTree` производит ключи по 5-байтному `i1+i2+i3` идентификатору ESP;
- `prfplus` реализует PRF+ для IPsec/IKE на базе Стрибога.

Не используйте эти механизмы вместо password hashing. Они расширяют ключи, но
не делают слабый пользовательский пароль стойким к offline-перебору.

## Источники

- [Openwall yescrypt](https://www.openwall.com/yescrypt/)
- [Go `crypto/pbkdf2`](https://pkg.go.dev/crypto/pbkdf2)
