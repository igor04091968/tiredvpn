# PFX и зашифрованные ключи ГОСТ

Пакет `pfx` предоставляет два профиля PKCS #12: контейнер с паролем по
RFC 9548 и адресный транспорт ключа по Р 1323565.1.041-2022. Низкоуровневые
функции парольного PFX и зашифрованного PKCS #8 находятся в `gostx509`.

## Парольный контейнер

```go
der, err := pfx.MarshalPassword(key, cert, chain, password)
if err != nil {
    return err
}
loadedKey, loadedCert, loadedChain, err := pfx.ParsePassword(der, password)
```

Здесь `key` — закрытый ключ, `cert` — соответствующий сертификат,
`chain` — дополнительные сертификаты. `ParsePassword` проверяет внешний MAC
перед разбором ключа и сертификатов. Это не подтверждает доверие к цепочке;
её проверяйте отдельно. Парольные байты задаёт вызывающий код как UTF-8.
Профиль по умолчанию использует PBKDF2 со Стрибогом и аутентифицированный
Кузнечик CTR-ACPKM-OMAC внутри PKCS #8.

`MarshalPasswordWithOptions` принимает `gostx509.EncryptedPKCS8Options`:
`Magma` выбирает Магму, `Iterations` задаёт число итераций PBKDF2. Для
совместимости со старыми реализациями есть `Legacy28147`, но этот вариант
зашифрованного PKCS #8 сам по себе не аутентифицирует шифртекст. Используйте
его только внутри контейнера с проверяемым MAC.

Если нужен только зашифрованный закрытый ключ, без PFX, используйте
`gostx509.MarshalEncryptedPKCS8PrivateKey` и
`gostx509.ParseEncryptedPKCS8PrivateKey`.

## Контейнер для получателей

`MarshalForRecipients` защищает ключ для перечисленных получателей и
подписывает AuthenticatedSafe. В этом фрагменте `key` и `recipientKey` имеют
тип `*gost3410.PrivateKey`, `signer` реализует `crypto.Signer`:

```go
protection := pfx.RecipientProtection{
    Recipients:        []*gostx509.Certificate{recipientCert},
    SignerCertificate: signerCert,
    Signer:            signer,
    Algorithm:         keywrap.AlgorithmKuznechik,
}
der, err := pfx.MarshalForRecipients(key, cert, chain, protection)
if err != nil {
    return err
}
container, err := pfx.ParseForRecipient(der, recipientCert, recipientKey)
if err != nil {
    return err
}
// container.Key, container.Certificate, container.Chain, container.Signers
// Проверить доверие к подписантам и цепочке перед использованием ключа.
```

Допустима `keywrap.AlgorithmMagma`. Для получателей, понимающих только
ГОСТ 28147-89/CryptoPro, используйте `keywrap.AlgorithmCryptoPro`; поле
`LegacyParamSet` позволяет выбрать набор подстановок A/B/C/D/Z.

`ParseForRecipient` математически проверяет подпись AuthenticatedSafe до
расшифрования. Сертификаты подписантов вложены в контейнер и не становятся
доверенными автоматически. Приложение должно проверить их цепочки и то, что
подписант был вправе передавать этот ключ. Возвращённые сертификаты могут
ссылаться на входной DER, поэтому сохраняйте его живым и неизменным.

См. также [CMS](cms.md), [X.509](x509.md) и
[миграцию на v3](migration-v3.md).
