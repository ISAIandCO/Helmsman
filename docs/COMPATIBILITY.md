# Совместимость

«Реализовано» означает импорт, проверку конфигурации движком, запуск, остановку и обработку ошибки. Проверки локального клиента с локальным сервером не доказывают совместимость со всеми провайдерами. Фактические испытания см. в TESTING.md и журнале GitHub Actions.

| Протокол / версия | Движок | Транспорт / возможности | Импорт | Ограничения |
|---|---|---|---|---|
| VLESS | sing-box 1.14.3 | TCP, TLS, REALITY, Vision, WS, gRPC, HTTP/HTTPUpgrade, QUIC по возможностям движка; XUDP | `vless://`, sing-box outbound JSON | Нет XHTTP, VLESS encryption, TCP HTTP-header camouflage и Xray-specific extra; неизвестные параметры отклоняются |
| VMess | sing-box | TCP, WS/gRPC/HTTP/HTTPUpgrade, TLS | Base64 `vmess://`, JSON | Старые нестандартные URI и обёртки требуют экспорта в JSON |
| Trojan | sing-box | TLS, TCP/UDP; V2Ray transport через JSON | `trojan://`, JSON | Trojan-Go plugins не запускаются |
| Shadowsocks | sing-box | AEAD и SS2022, TCP/UDP по методу | SIP002 `ss://`, legacy Base64 URI, JSON | SIP003 плагины не запускаются; 2022-ключ должен иметь правильную длину |
| Hysteria2 | sing-box | QUIC/UDP, Salamander, hopping (JSON/URI ports) | `hysteria2://`, `hy2://`, JSON | Нужна доступность UDP; неизвестные extensions не игнорируются |
| Hysteria1 | sing-box | Отдельный протокол QUIC/UDP, auth/obfs, скорости | `hysteria://`, JSON | Не совместим на проводе с Hysteria2; не UDP-fakeTCP/wechat |
| TUIC v5 | sing-box | QUIC/UDP | `tuic://`, JSON | TUIC v4 не заявляется; congestion/relay параметры в ссылке или JSON |
| AnyTLS | sing-box | TLS/TCP | `anytls://`, JSON | UDP зависит от реализации сервера/движка; не произвольные AnyReality расширения |
| SOCKS5 | sing-box | TCP, UDP ASSOCIATE при поддержке сервера | `socks5://`, `socks://`, JSON | UDP у сервера обязателен для игр |
| HTTP(S) CONNECT | sing-box | TCP | `http://`, `https://`, JSON | Произвольный UDP не поддерживается |
| WireGuard | sing-box endpoint | Userspace WG, несколько Peer, IPv4/IPv6, keepalive | `.conf`, endpoint JSON | AllowedIPs сохраняются; shell hooks, Table/FwMark, внешние файлы отклоняются; для полного туннеля нужны соответствующие AllowedIPs |
| AmneziaWG 1.0/1.5/2.0 | Throne sing-box + Throne wireguard-go | Jc/Jmin/Jmax, S1–S4, H1–H4/ranges, I1–I5 | `.conf`, JSON `amnezia_wg`, поддерживаемый self-hosted `vpn://` | Требуется совпадение параметров сервера. I-пакеты и диапазоны зависят от версии сервера |
| AmneziaWG 3.x | Тот же закреплённый fork | Поля HeaderProtectionKey, ContentPaddingAddition и таймеры/ranges приняты схемой fork | `.conf` и JSON | Отдельная совместимость с реальными серверами 3.0/3.1 пока не подтверждена; не смешивать названия версий с доказанной совместимостью |
| OpenVPN TLS | sing-box 1.14.3 endpoint | UDP/TCP, CA, клиентский сертификат/ключ, логин/пароль, tls-auth/tls-crypt/v2 через поддерживаемый JSON/inline | Автономный `.ovpn`, `openvpn-client` JSON | Только TUN/userspace, не TAP/L2, PKCS#11, внешние scripts/plugins, файлы ключей, интерактивный SSO/MFA или устаревший static-key. Неизвестные директивы отклоняются. Compression не импортируется. Pushed OS routes/DNS не применяются: управляет Helmsman |
| AmneziaVPN export | По протоколу внутри | Client export с готовым WG/AWG/OpenVPN config; Qt qCompress `vpn://` | `vpn://`, JSON containers | Не SSH/admin access, Amnezia Gateway/API subscription, XRay/XHTTP containers или произвольная новая схема. Для них экспортируйте готовый `.conf`/`.ovpn`/VLESS URI |
| ZeroTier Agent 1.16.2 | Отдельный MPL Agent | Виртуальная Ethernet/LAN, join/leave, Node ID, ожидание авторизации | `zerotier://<network-id>`, GUI Network ID | Только выбранная сеть, без default/global routes и DNS от контроллера; не одновременно с VPN, не exit-node/full tunnel, без SSO |

Все типы профилей используют общий API сервиса. Ошибка запуска, завершение процесса, отказ проверки конфигурации и ошибки подписок показываются без публикации исходных ключей. Статус `running` для интернет-VPN подтверждает процесс/TUN, а не удалённую доступность. Для неё предусмотрена отдельная TCP/TLS-проверка.

Подписки: UTF-8 список URI, Base64 списка URI, массив outbound JSON, sing-box JSON с outbounds/endpoints. Импортируются соединения; маршрутизация, services/inbounds и чужая системная политика не импортируются. Неизвестный узел в подписке отклоняет обновление целиком, чтобы не терять данные молча. Clash YAML, QR-коды и зашифрованные архивы в первой версии не разбираются.

Сочетания: один основной sing-box **или** один AWG sing-box **или** один ZeroTier Agent. Фоновые процессы не запускаются заранее. Пользователь может выбрать любой интернет-профиль для всех VPN-правил; разные VPN-профили в отдельных правилах одновременно пока не поддерживаются.
