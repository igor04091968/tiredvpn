# Релизы форка

## Доступные сборки

| Компонент | Релиз | Состав |
| --- | --- | --- |
| Ядро Linux | [1.12.2-igor.4](https://github.com/igor04091968/tiredvpn/releases/tag/v1.12.2-igor.4) | Архивы amd64 и arm64; `checksums.txt` приложен к релизу. |
| Android-клиент | [1.12.1-igor.7](https://github.com/igor04091968/tiredvpn-android/releases/tag/v1.12.1-igor.7) | APK, versionCode 34; ABI `arm64-v8a`, `armeabi-v7a`, `x86_64`. |
| F-Droid | [Пользовательский репозиторий](https://igor04091968.github.io/tiredvpn-fdroid/) | Каталог проекта на GitHub Pages. Его нужно добавить вручную; приложение не опубликовано в официальном каталоге F-Droid.org. |

Для Android доступен также [APK напрямую из GitHub Release](https://github.com/igor04091968/tiredvpn-android/releases/download/v1.12.1-igor.7/TiredVPN-1.12.1-igor.7.apk). SHA-256 этого файла: `1dc88429f6f5f6c35e30045df6fb310fd3a41f09f41ec7118de60d3425f4d63c`. Сборка подписана ключом проекта; SHA-256 сертификата подписи: `34193b315f837421f50d3cfbd3f528fe2f1f9de0313d880bf25bed61c7e41539`.

Чтобы добавить F-Droid-каталог, используйте адрес с fingerprint:

```text
https://igor04091968.github.io/tiredvpn-fdroid/fdroid/repo?fingerprint=AD9A2A670A24AEBF3C2E4D1106492DF91D4303F9BD33BBD444EB9ED11C32911D
```

Fingerprint здесь относится к ключу подписи индекса F-Droid. Он отличается от сертификата подписи APK.

## Состав и статус изменений

Ядро Linux и Android-клиент имеют отдельные версии и выпускаются раздельно. В актуальных материалах форка описаны экспериментальный профиль ГОСТ TLS 1.3 с проверкой pin сертификата и вариант REALITY Single Flight. Издание нового клиента само по себе не обновляет серверы и не подтверждает доступность соединения во всех сетях.

Профиль ClientHello настроен по собственным образцам CryptoPro CSP 5.0 R4, но приложение и сервер используют реализацию Go и библиотеку ГОСТ; CryptoPro не включён в APK или бинарные файлы. Профиль является приближением, а эффективность при сетевой фильтрации не доказана. Ротация сертификата поддерживает временное одновременное доверие двум явно заданным pin; неизвестный сертификат автоматически не принимается.

См. также: [ротация сертификата](../GOST-IMPLEMENTATION.md#certificate-rotation-with-two-trusted-pins), [REALITY Single Flight](reality-singleflight.md), [профиль ClientHello](gost-cryptopro-clienthello.md).
