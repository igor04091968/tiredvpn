# CMS: подписи, шифрование и метки времени

Пакет `cms` работает с ASN.1 CMS SignedData и EnvelopedData. Он не читает
удалённый в v3 собственный JSON-формат `cms.Envelope`. Для переноса данных из
v2 нужно отдельно расшифровать старый контейнер старой версией библиотеки и
создать новый CMS-контейнер.

## SignedData

`SignDetached` создаёт отделённую подпись, `SignAttached` включает содержимое
в контейнер. Для большого потока используйте `SignDetachedReader` или
`SignAttachedTo`; последний записывает BER по частям и при ошибке записи может
оставить частичный результат. Варианты `*WithOptions` позволяют задать OID
содержимого, время подписания и дополнительные сертификаты.

Следующий фрагмент предполагает уже загруженные `cert` типа
`*gostx509.Certificate` и `signer` типа `crypto.Signer`:

```go
content := []byte("document")
der, err := cms.SignDetached(content, cert, signer)
if err != nil {
    return err
}
signed, err := cms.ParseSignedData(der)
if err != nil {
    return err
}
results, err := signed.Verify(content)
if err != nil {
    return err
}
if len(results) == 0 {
    return errors.New("CMS не содержит подписантов")
}
for _, result := range results {
    if result.Err != nil {
        return result.Err
    }
    // Проверить доверие к result.Signer.Certificate отдельно.
}
```

Для вложенной подписи вызывайте `signed.Verify(nil)`. `Verify` проверяет
криптографию каждой подписи и возвращает результат для каждого подписанта;
само присутствие сертификата в CMS не делает его доверенным. Проверка цепочки,
назначения сертификата, срока действия и отзыва — задача приложения. Если
сертификаты подписантов передаются отдельно, используйте
`VerifyReaderWithCertificates`.

`ParseSignedData` может ссылаться на переданный DER. Сохраняйте входной буфер
живым и неизменным, пока используете результат. Для вложенного BER-содержимого
`ContentReader` позволяет читать части без сборки всего сообщения в один срез.

## EnvelopedData

Для получателей с ключами ГОСТ Р 34.10-2012 применяйте современный профиль
KEG/KExp15 и CTR-ACPKM:

```go
der, err := cms.EncryptEnveloped2012(
    plaintext,
    []*gostx509.Certificate{recipientCert},
    keywrap.AlgorithmKuznechik,
)
if err != nil {
    return err
}
envelope, err := cms.ParseEnvelopedData(der)
if err != nil {
    return err
}
opened, err := envelope.DecryptUnauthenticated(recipientCert, recipientKey)
```

Здесь `recipientKey` имеет тип `*gost3410.PrivateKey`. Вместо Кузнечика можно
выбрать `keywrap.AlgorithmMagma`. `EncryptEnveloped2012To` потоково записывает
BER и ограничивает размер рабочего буфера; при ошибке вывода контейнер может
оказаться частичным. Для ГОСТ Р 34.10-2001 с ГОСТ 28147-89 используйте
`EncryptEnveloped` или `EncryptEnvelopedTo`. Для совместимости с получателями
ГОСТ 2012, использующими старый CryptoPro-профиль, предусмотрены
`EncryptEnvelopedLegacy` и `EncryptEnvelopedLegacyWithParamSet` с наборами
подстановок A/B/C/D/Z.

CMS EnvelopedData защищает ключ содержимого, но не подтверждает целостность
самого содержимого. `DecryptUnauthenticated` и `DecryptUnauthenticatedTo`
называются так намеренно: если требуется целостность, проверьте отдельную
подпись над расшифрованными данными до их использования.

## RFC 3161 и CAdES-T

`CreateTimeStampRequest` создаёт запрос для службы времени; приложение само
передаёт его TSA. `ParseTimeStampResponse` проверяет формат ответа и nonce,
`ParseTimeStampToken` разбирает токен. Далее отдельно вызывайте
`VerifyImprint`, `VerifySignatures` и `ValidateTSASigner`. Проверка цепочки TSA,
срока действия и отзыва сертификата также остаётся у приложения.

`AddSignatureTimeStamp` добавляет токен как неподписанный атрибут выбранного
подписанта. После разбора `VerifySignatureTimeStamps` возвращает ошибки по
подписантам и их токенам; доверие к TSA и пригодность времени для конкретного
документа проверяются отдельно.

См. также [миграцию на v3](migration-v3.md), [X.509](x509.md) и
[безопасность](security.md).
