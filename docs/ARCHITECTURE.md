# Архитектура и принятые решения

- Python standard library обслуживает приватное состояние и Unix JSON RPC; Qt/PySide6 используется только GUI. Это небольшой нативный клиент без браузерного runtime и HTTP-порта управления.
- GUI и непривилегированный Python backend Decky обращаются к одному `/run/helmsman/control.sock`. Проверяются `SO_PEERCRED` и назначенный при установке UID (root также администратор). Frontend Decky использует `@decky/api` и стандартные `@decky/ui` для фокуса геймпада. Закрытие клиентов не останавливает сервис.
- Программа и состояние размещены непосредственно в root-owned `/opt/helmsman` и `/opt/helmsman/state` на разделе `/opt` SteamOS. Привилегированная служба не исполняет файлы из пользовательского каталога `/home/deck`. `ProtectHome=yes` скрывает домашние каталоги; `ProtectSystem=strict` и `ReadWritePaths` разрешают запись только в состояние и runtime. `RequiresMountsFor` дожидается `/opt/helmsman`. В `/var/lib` нет ссылок совместимости. До остановки службы проверяется место для новой копии с запасом, затем версия переключается атомарно.
- Служба управляет ресурсами root, но основной движок запускается под отдельным `helmsman-engine` с CAP_NET_ADMIN/CAP_NET_RAW. Этот UID — единственное общее исключение firewall, пользовательские программы не должны его использовать. Для TUN используются таблица 31800, priorities 31800–31811, интерфейс helmsman0. Чужие таблицы не очищаются.
- Общий sing-box обслуживает TUN, FakeIP/DNS, упорядоченные правила, прокси и userspace endpoints WG/OpenVPN. Для AmneziaWG используется отдельный sing-box fork Throne: его WireGuard API и obfuscation уже поддерживаются upstream Throne; собственная реализация протоколов не нужна. Одновременно работает один движок.
- ZeroTier собран из того же закреплённого source с `ZT_NONFREE=0`, `ZT_SSO_SUPPORTED=0`. Он запускается со своим home/портом, без вмешательства в системный zerotier-one. До join записывается локальная политика allowDefault/allowGlobal/allowDNS=0. Это отдельный режим виртуальной LAN, не интернет-VPN.
- Политика firewall переживает завершение движка и службы; удаляется по явному disconnect. Во время работы все внешние сокеты приложений направляются в TUN. Прямые исключения обслуживает движок. При его гибели блокируется весь интернет; LAN/DHCP/NDP остаются согласно настройкам. Ранний boot unit ставится перед NetworkManager. Отдельная проверка на SteamOS необходима.
- Конфигурации записываются через fsync+atomic replace, mode 0600. Обновления подписок сначала целиком разбираются и проверяются, затем заменяются. Активный удалённый из подписки узел сохраняется. Смена маршрутизации перезапускает выбранный движок при сохранённой защите.
- Удалённые конфиги не могут импортировать shell hooks, плагины, file paths, detour/interface bindings или серверные сервисы. Приватные URL и ключи не пишутся в обычный лог, лог движка выключен; диагностика даёт безопасные категории и exit code. Зашифрованное хранилище/интеграция с KWallet пока отсутствуют: защита секретов — права файлов и системный доступ.
- Сервис проверяет физическую таблицу маршрутов каждые 15 секунд и большой интервал после сна; повтор подключения ограничен настройкой. Нет постоянного ping/STUN или периодических проверок Steam Store: end-to-end probe запускается пользователем. Нагрузка и энергопотребление на Steam Deck требуют измерения.
- `running` означает process+TUN, `connected` у ZeroTier — статус OK от агента. Проверка VPN через аутентифицированный локальный SOCKS-inbound принудительно проходит через выбранный профиль и проверяет HTTPS Steam Store. Этот inbound слушает только loopback, порт/случайный пароль не публикуются.

## Проверенные первичные источники

Состояние и commit фиксируются в `scripts/build-engines.py` и `BUILD.json` релиза. Документация сайтов может описывать следующую, ещё не выбранную версию; совместимость проверяется схемой закреплённых исходников.

- [SteamOS Desktop FAQ](https://help.steampowered.com/en/faqs/view/671A-4453-E8D2-323C): неизменяемый системный образ, риск потери pacman-установок при обновлении.
- [Decky plugin template](https://github.com/SteamDeckHomebrew/decky-plugin-template), [frontend/backend API](https://wiki.deckbrew.xyz/en/plugin-dev/backend-frontend-communication).
- [sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/), [VLESS](https://sing-box.sagernet.org/configuration/outbound/vless/), [WireGuard endpoint](https://sing-box.sagernet.org/configuration/endpoint/wireguard/), [OpenVPN Client](https://sing-box.sagernet.org/configuration/endpoint/openvpn-client/).
- [Throne](https://github.com/throneproj/Throne): изучены core/go.mod, импортеры/редактор WireGuard/AmneziaWG и закреплённые forks. Используется сетевой fork, Qt-интерфейс написан отдельно.
- [NekoBox_SF](https://github.com/ISAIandCO/NekoBox_SF): ориентир для профилей, HWID, выбора маршрутов и явного разделения логики подключения/диагностики.
- [Hiddify](https://github.com/hiddify/hiddify-app): ориентир для быстрого подключения и управления подписками, код интерфейса не копируется.
- [AmneziaVPN](https://github.com/amnezia-vpn/amnezia-client): изучены importController/exportController, qCompress-кодировка vpn://, containers/last_config и экспорт native конфигураций.
- [AmneziaWG documentation](https://docs.amnezia.org/documentation/amnezia-wg/): версии протокола и новые obfuscation-поля. Совпадение названий параметров не заменяет испытаний с сервером.
- [Remnawave HWID](https://docs.rw/features/hwid-device-limit/): x-hwid, ограничения формата. Для иных провайдеров предусмотрена настройка заголовка/query.
- [ZeroTier CLI](https://docs.zerotier.com/cli/), [client configuration](https://docs.zerotier.com/config/), исходники OneService.cpp: join-статусы и policy локальных маршрутов.
- [Российские списки](https://github.com/runetfreedom/russia-v2ray-rules-dat): общественные источники, не утверждение о блокировке в конкретной сети.

## Локальный API

Одна JSON-строка `{"method":"status","params":{}}`, ответ `{"ok":true,"result":...}` или `{"ok":false,"error":"безопасное сообщение"}`. Ограничение входного запроса 8 МиБ, таймаут 90 с, максимум 8 обработчиков. Для доступа нужен назначенный UID или root.

Команды: status, configuration (с секретами, только доверенный локальный клиент), diagnostics, import, profile_save/rename/delete, connect/disconnect/select, preset, subscription_save/delete, subscriptions_update, hwid, rules_save, settings_save, list_save/delete, lists_update, probe. Decky backend разрешает только повседневное подмножество; configuration ему не доступна.

`Helmsman ctl status`; `Helmsman ctl preset '{"preset":"full"}'`; `Helmsman ctl disconnect`.

## XHTTP и WARP

XHTTP сохраняется как нормализованный клиентский outbound в той же базе профилей. Runtime проверяет Xray и sing-box до смены подключения, запускает Xray без capabilities под выделенным engine UID и связывает его с sing-box через loopback SOCKS5 со случайным паролем/портом. Только sing-box управляет TUN и DNS. При обнаружении завершения Xray сервис останавливает TUN-клиент, сохраняет guard и восстанавливает оба процесса. Disconnect/удаление останавливают оба процесса и удаляют временные конфигурации. Bootstrap для hostname XHTTP endpoint задаётся тем же явным IP DNS; запросы приложений остаются в общей DNS-политике. Для основного TLS используется системное CA-хранилище, проверка не отключается.

WARP-регистрация вызывается только RPC `warp_generate` с явным `accept_terms=true`. wgcf работает с отдельным приватным account.toml; stdout/stderr подавлены, поскольку upstream печатает ключи и токены. Возвращается только ID/понятный результат. Account переживает ошибки generate и обновления. Публичный локальный AWG/CPS-шаблон применяется после получения WG-профиля; регистрация и криптография не реализуются заново. Сигнатура I1 берётся из лицензированного upstream, не из приватной конфигурации пользователя.
