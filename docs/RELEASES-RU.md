# Релизы форка

| Компонент | Скачать | Что включено |
| --- | --- | --- |
| Ядро Linux 1.12.2-igor.4 | [Релиз и архивы amd64/arm64](https://github.com/igor04091968/tiredvpn/releases/tag/v1.12.2-igor.4) | REALITY Single Flight, ГОСТ TLS 1.3, профиль ClientHello по образцу CryptoPro, клиентская поддержка двух pin |
| Android 1.12.1-igor.4 | [APK](https://github.com/igor04091968/tiredvpn-android/releases/tag/v1.12.1-igor.4) | Те же стратегии, protect сокетов до TCP connect, импорт двух pin и versionCode 31 |

Linux-архивы содержат статический CLI/server binary; контрольные суммы опубликованы в checksums.txt. Android подписан прежним ключом форка и включает arm64-v8a, armeabi-v7a и x86_64. Код нативного ядра Android закреплён на fce4f440843f0f0fad3cacdb236f5729a489f5be, исходники приложены автоматически к тегу GitHub.

Тесты ротации выполнялись с -race: принятие обоих pin, отказ от незнакомого сертификата, перевыпуск с тем же ключом, удаление старого pin и проверка срока сертификата. Go vet и 56 Android-тестов прошли. После сборки APK проверяются подпись, версия, JNI-хэши и выравнивание 16 КБ. Профиль ClientHello остаётся приближением CryptoPro; выигрыш при активной фильтрации не доказан.

На двух работающих серверах остаётся версия 1.12.2-igor.3. Новый клиент совместим с ними; публикация релиза не обновляет серверы и не меняет сертификаты. Новый APK ещё нужно проверить на телефоне через МТС.

[Ротация сертификата](../GOST-IMPLEMENTATION.md#certificate-rotation-with-two-trusted-pins) · [REALITY Single Flight](reality-singleflight.md) · [ГОСТ ClientHello](gost-cryptopro-clienthello.md)
