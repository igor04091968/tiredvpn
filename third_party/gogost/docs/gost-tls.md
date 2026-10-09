# ГОСТ TLS как подключаемая Go-библиотека

Пакеты `gosttls`, `gostx509` и `gosthttp` реализуют профиль ГОСТ TLS 1.3 из
[RFC 9367](https://www.rfc-editor.org/rfc/rfc9367.html) внутри обычного Go-модуля.
Заменять Go SDK, патчить `GOROOT` или собирать специальную версию `net/http` не
нужно.

Команды установки v3.0.0 и работы с локальным checkout приведены в
[быстром старте](quick-start.md).

Требуется Go 1.27.1 или новее. TLS-core перенесён из точного релиза
[`go1.27.1`](https://go.dev/doc/devel/release#go1.27.1), включающего исправления
безопасности `crypto/tls`.

## Какой пакет использовать

| Пакет | Назначение |
| --- | --- |
| `gosttls` | TLS-соединение поверх любого `net.Conn`, `Dial`, `Listen`, клиент и сервер |
| `gostx509` | X.509, PKIX и PKCS #8 для ключей и сертификатов ГОСТ 34.10-2012 |
| `gosthttp` | HTTP/1.1, HTTP/2, HTTP/HTTPS CONNECT и SOCKS5 через стандартный `net/http` |

`*gosttls.Conn` реализует `net.Conn`, поэтому его можно передать коду любого
TCP-протокола, которому достаточно потокового соединения.

Обычный `gosttls.Config{}` использует смешанный ГОСТ-first профиль: C103–C106,
ГОСТ groups/signatures, затем стандартные TLS 1.3 suites, ML-KEM hybrid groups,
ML-DSA и X25519 fallback. Это позволяет одному transport работать и с ГОСТ, и
с обычными TLS 1.3 endpoint. Чистая группа `gosttls.MLKEM1024` поддерживается
при явном выборе через `CurvePreferences`, но не включена по умолчанию.
`gosttls.GOSTConfig` остаётся строгим профилем RFC 9367 и TLS 1.3-only.

После полного handshake `ConnectionState.LocalCertificate` содержит локальную
цепочку, фактически переданную peer. Для возобновлённой сессии поле пустое.

## Сертификаты и доверенные корни

Серверный сертификат и закрытый ключ загружаются почти так же, как в
`crypto/tls`. Закрытый ключ ГОСТ должен быть записан в PKCS #8:

```go
certificate, err := gosttls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    log.Fatal(err)
}
```

Корни ГОСТ следует добавлять явно через `gostx509.CertPool`:

```go
caPEM, err := os.ReadFile("gost-ca.pem")
if err != nil {
    log.Fatal(err)
}
roots := gostx509.NewCertPool()
if !roots.AppendCertsFromPEM(caPEM) {
    log.Fatal("gost-ca.pem не содержит сертификатов")
}
```

`gostx509` также предоставляет `ParseCertificate`, `CreateCertificate`,
`ParsePKIXPublicKey`, `MarshalPKIXPublicKey`, `ParsePKCS8PrivateKey` и
`MarshalPKCS8PrivateKey`. Обычные RSA, ECDSA и Ed25519 сертификаты передаются
системному `crypto/x509`, а цепочки ГОСТ проверяются локальным верификатором.

## TCP-клиент

`GOSTConfig` клонирует конфигурацию и включает строгий профиль ГОСТ TLS 1.3:

```go
config := gosttls.GOSTConfig(&gosttls.Config{
    RootCAs:    roots,
    ServerName: "server.example",
})

conn, err := gosttls.Dial("tcp", "server.example:8443", config)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

_, err = conn.Write([]byte("hello\n"))
```

Для `context.Context` используйте `gosttls.Dialer.DialContext`. Если TCP-сокет
уже открыт, его можно обернуть вручную:

```go
secureConn := gosttls.Client(rawConn, config)
if err := secureConn.HandshakeContext(ctx); err != nil {
    return err
}
```

## TCP-сервер

```go
certificate, err := gosttls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    log.Fatal(err)
}
config := gosttls.GOSTConfig(&gosttls.Config{
    Certificates: []gosttls.Certificate{certificate},
})

listener, err := gosttls.Listen("tcp", ":8443", config)
if err != nil {
    log.Fatal(err)
}
defer listener.Close()

for {
    conn, err := listener.Accept()
    if err != nil {
        log.Fatal(err)
    }
    go handle(conn) // conn имеет интерфейс net.Conn
}
```

Для существующего `net.Listener` используйте
`gosttls.NewListener(listener, config)`.

## HTTP-клиент через net/http

```go
config := gosttls.GOSTConfig(&gosttls.Config{
    RootCAs:    roots,
    ServerName: "server.example",
})
client := gosthttp.NewClient(config)

response, err := client.Get("https://server.example:8443/api")
if err != nil {
    log.Fatal(err)
}
defer response.Body.Close()
```

`NewTransport` автоматически выбирает HTTP/2 (`h2`) либо HTTP/1.1 по ALPN и
передаёт уже расшифрованный `net.Conn` в публичный
`http.Transport.NewClientConn`. Повторного TCP/TLS-подключения после ALPN нет.
`NewHTTP1Transport` оставлен для endpoint, где нужно принудительно запретить H2.
При `NewTransport(nil)` origin и HTTPS-proxy получают отдельные session cache
по 128 записей; переданная конфигурация сохраняет собственную cache policy.

Если нужен собственный `http.Client`, установите транспорт явно:

```go
client := &http.Client{
    Transport: gosthttp.NewTransport(config),
    Timeout:   15 * time.Second,
}
```

### HTTP, HTTPS и SOCKS5 proxy

По умолчанию `NewTransport` использует `gosthttp.ProxyFromEnvironment`.
Сначала учитывается подходящая переменная `HTTP_PROXY` или `HTTPS_PROXY`, затем
`ALL_PROXY` как fallback; `NO_PROXY` применяется в обоих случаях. Явная
настройка HTTPS proxy с Basic auth выглядит так:

```go
proxyURL, err := url.Parse("https://user:password@proxy.example:8443")
if err != nil {
    log.Fatal(err)
}

transport := gosthttp.NewTransport(originTLSConfig)
transport.Proxy = http.ProxyURL(proxyURL)
transport.ProxyTLSClientConfig = proxyTLSConfig // обычный или ГОСТ TLS
transport.ProxyConnectHeader = http.Header{
    "X-Proxy-Tenant": {"production"},
}

client := &http.Client{Transport: transport}
```

Транспорт сначала устанавливает HTTP/1.1 CONNECT tunnel, затем выполняет ровно
один origin TLS handshake и использует тот же tunnel для H1 keep-alive или H2
multiplexing. Динамические заголовки задаются через `GetProxyConnectHeader`, а
ответ до проверки статуса доступен через `OnProxyConnectResponse`. Для proxy
предусмотрены отдельные `ProxyTLSHandshakeTimeout` и `ProxyConnectTimeout`.

SOCKS5 с RFC 1929 username/password настраивается через userinfo URL:

```go
proxyURL, err := url.Parse("socks5://user:password@proxy.example:1080")
if err != nil {
    log.Fatal(err)
}

transport := gosthttp.NewTransport(originTLSConfig)
transport.Proxy = http.ProxyURL(proxyURL)
transport.ProxyConnectTimeout = 30 * time.Second
client := &http.Client{Transport: transport}
```

`socks5` и `socks5h` имеют одинаковую семантику Go 1.27.1: доменное имя origin
передаётся SOCKS-серверу, локальное DNS-разрешение не выполняется. Для HTTPS
после SOCKS `CONNECT` выполняется один origin ГОСТ TLS handshake; выбранный по
ALPN HTTP/2 мультиплексируется внутри того же TCP-туннеля. Заголовки и callbacks
HTTP CONNECT к SOCKS не применяются.

Сам SOCKS5 не шифрует участок между клиентом и proxy, а RFC 1929 передаёт
username/password без конфиденциальности. Используйте SOCKS-сервер только в
доверенной сети или через внешний защищённый канал. ГОСТ TLS продолжает
защищать HTTPS-трафик от клиента до origin.

## HTTP-сервер через net/http

```go
server := &http.Server{
    Addr: ":8443",
    Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if state, ok := gosthttp.ConnectionState(r); ok {
            log.Printf("suite=%s", gosttls.CipherSuiteName(state.CipherSuite))
        }
        _, _ = w.Write([]byte("GOST TLS\n"))
    }),
}

listener, err := net.Listen("tcp", server.Addr)
if err != nil {
    log.Fatal(err)
}
log.Fatal(gosthttp.Serve(server, listener, config))
```

`Serve` разрешает H1 и H2 по умолчанию. Для явной политики используйте
`http.Server.Protocols`; bridge снаружи всегда остаётся зашифрованным:

```go
protocols := new(http.Protocols)
protocols.SetHTTP1(true)
protocols.SetHTTP2(true)
server.Protocols = protocols
```

`ServeHTTP1` принудительно оставляет только HTTP/1.1. ALPN gate отклоняет H2
preface без `h2` ALPN и HTTP/1.1 bytes после выбора `h2`.

Нужно вызывать `gosthttp.Serve`, а не `http.Server.ServeTLS`: стандартный
`net/http` жёстко связан с конкретным типом `crypto/tls.Conn`. По той же причине
`http.Request.TLS` для такого соединения равен `nil`; состояние доступно через
`gosthttp.ConnectionState`. На клиенте `http.Response.TLS` также равен `nil`,
а полное состояние возвращает `gosthttp.ResponseConnectionState(response)`.
Частично заполненное фиктивное `crypto/tls.ConnectionState` не создаётся:
`httptrace.TLSHandshakeDone` получает нулевое стандартное состояние, а полное
ГОСТ-состояние читается через API выше.

### `httputil.ReverseProxy`

ГОСТ TLS можно использовать на upstream-стороне обычного reverse proxy:

```go
upstream, _ := url.Parse("https://backend.example:8443")
reverse := &httputil.ReverseProxy{
    Rewrite: func(request *httputil.ProxyRequest) {
        request.SetURL(upstream)
        request.SetXForwarded()
        // ProxyRequest.SetXForwarded смотрит на Request.TLS, который для
        // gosthttp намеренно nil; внешний listener здесь всегда защищён.
        request.Out.Header.Set("X-Forwarded-Proto", "https")
    },
    Transport: gosthttp.NewTransport(upstreamTLSConfig),
}

frontend := &http.Server{Addr: ":443", Handler: reverse}
listener, err := net.Listen("tcp", frontend.Addr)
if err != nil {
    log.Fatal(err)
}
log.Fatal(gosthttp.Serve(frontend, listener, frontendTLSConfig))
```

Если `X-Forwarded-Proto` формируется другим middleware, определяйте защищённое
соединение через `gosthttp.ConnectionState(request)`, а не через `request.TLS`.

## Взаимная аутентификация

Сервер:

```go
serverConfig := gosttls.GOSTConfig(&gosttls.Config{
    Certificates: []gosttls.Certificate{serverCertificate},
    ClientAuth:   gosttls.RequireAndVerifyClientCert,
    ClientCAs:    clientRoots,
})
```

Клиент добавляет свой сертификат в `Certificates`, а корень сервера — в
`RootCAs`. При возобновлении сессии библиотека повторно проверяет сохранённую
цепочку по текущим `RootCAs` или `ClientCAs`; смена trust store не обходится
старым session ticket.

## Реализованный профиль RFC 9367

| Часть профиля | Реализация |
| --- | --- |
| Cipher suites | `0xC103`–`0xC106`: Кузнечик/Магма, MGM L/S |
| TLS key schedule и transcript | Стрибог-256 |
| Record keys | `TLSTREE` с параметрами соответствующего cipher suite |
| Named groups | `0x0022`–`0x0028`, TC26 256 A–D и 512 A–C |
| Key agreement | VKO ГОСТ 34.10-2012, формат key share из RFC 9367 |
| Signature schemes | `0x0709`–`0x070F`, TC26 256 A–D и 512 A–C |
| Сертификаты и ключи | X.509/PKIX и PKCS #8 ГОСТ 34.10-2012 |
| Session resumption | TLS 1.3 session tickets с key schedule Стрибог-256 |

Двунаправленная совместимость вручную проверена на Linux/amd64 со сторонней
реализацией [gostls13](http://www.gostls13.stargrave.org/) из tag
`go1.25.0-gost`. Это сравнительная interop-проверка, а не эталон: нормативной
основой остаётся RFC 9367. Наша
реализация поочерёдно работала клиентом и сервером для всех suite `C103`–`C106`
с группой `GOSTCurve256A`. Та же проверка использовала сертификат X.509 и ключ
PKCS #8, созданные `gostx509`. Перед production-развёртыванием всё равно
проверяйте конкретную версию и конфигурацию второй стороны.

Чтобы оставить только конкретные разрешённые параметры, измените результат
`GOSTConfig` до первого использования:

```go
config := gosttls.GOSTConfig(base)
config.CipherSuitesTLS13 = []uint16{
    gosttls.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
}
config.CurvePreferences = []gosttls.CurveID{gosttls.GOSTCurve256A}
config.SignatureSchemes = []gosttls.SignatureScheme{
    gosttls.GOSTR34102012256A,
}
```

Конфигурацию нельзя изменять после того, как она начала использоваться
соединениями. Для нового набора параметров вызовите `Clone`.

## Ограничения и эксплуатация

- ГОСТ-профиль работает в TLS 1.3. Поддержка обычного TLS 1.2/1.3 в пакете не
  означает наличие устаревших ГОСТ cipher suites для TLS 1.2.
- `gosthttp` поддерживает HTTP/1.1, HTTP/2 до origin, HTTP/HTTPS CONNECT proxy и
  TCP CONNECT через SOCKS5. SOCKS5 GSSAPI, BIND, UDP ASSOCIATE, SOCKS-over-TLS и
  HTTP/2 как управляющий протокол до proxy не поддерживаются.
- QUIC полностью исключён из этой версии. Он будет реализован позже отдельным
  пакетом `gostquic`.
- Standalone ГОСТ-реализация не является FIPS-модулем и не заявляет режимы
  FIPS/BoringCrypto.
- ГОСТ-корни необходимо явно загрузить в `gostx509.CertPool`. Системный набор
  корней нельзя считать источником ГОСТ-сертификатов на всех платформах.
- Как и `crypto/tls`, пакет не выполняет автоматическую онлайн-проверку отзыва
  сертификата. Политику CRL/OCSP нужно реализовать на уровне приложения.
- Это программная библиотека, а не сертифицированное СКЗИ. Для среды, где
  обязательна сертификация реализации или защищённое хранение ключа, используйте
  утверждённый криптопровайдер и профиль эксплуатации.
- Транспортный слой основан на коде `crypto/tls` под BSD-лицензией; локальная
  копия включает проверки границ смены traffic secret, ограничение PSK и
  повторную проверку trust store при session resumption.

Проверка всех четырёх cipher suites, семи named groups, семи схем подписи,
взаимной аутентификации, session resumption, TCP-записей и HTTP-интеграции:

```bash
go test ./gost3410 ./gost34112012256 ./gost3412128 ./mgm ./gosttls ./gostx509 ./gosthttp
```

Race-проверка и benchmark/benchstat:

```bash
go test -race ./gost3410 ./gost34112012256 ./gost3412128 ./mgm ./gosttls ./gostx509 ./gosthttp
go test -tags purego ./...
go test -run '^$' -bench 'BenchmarkGOSTTLS13' -benchmem -count=10 ./gosttls > before.txt
go test -run '^$' -bench 'Benchmark(HTTP|CONNECT)' -benchmem -count=10 ./gosthttp >> before.txt
# повторить после изменения в after.txt
benchstat before.txt after.txt
```

Условия измерений и описание crypto/TLS/HTTP fast paths приведены в
[руководстве по производительности](performance.md).
