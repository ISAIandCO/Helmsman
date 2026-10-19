# Региональные маршруты: источники и ограничения

Проверено 2026-10-19. Страна — ручной фильтр каталога пресетов, язык и профиль сервера независимы. Применённый preset ID содержит страну; смена настройки country не меняет его. Старые full/ru-selective/ru-except/manual и приоритеты сохранены. Пользовательские правила идут перед правилами пресета, после служебных DNS/IPv6 и разрешённой LAN.

Ориентир Hiddify: [перечень регионов](https://github.com/hiddify/hiddify-app/blob/f26aadb351fb23c222e06fcf4f5350d0ba596bb9/lib/core/model/region.dart), [builtin bypassRegion](https://github.com/hiddify/hiddify-app/blob/f26aadb351fb23c222e06fcf4f5350d0ba596bb9/lib/features/route_rules/notifier/rules_notifier.dart), [region и настройки DNS](https://github.com/hiddify/hiddify-app/blob/f26aadb351fb23c222e06fcf4f5350d0ba596bb9/lib/features/settings/data/config_option_repository.dart). Оттуда взят подход независимого региона и обхода местных доменов/IP. Helmsman не копирует геоданные, профили или настройки DNS Hiddify: действующие DNS пользователя сохраняются, применение нового маршрута явно подтверждается кнопкой.

| Страна | Основание включения | Доменные исключения | IP-источник |
| --- | --- | --- | --- |
| Россия | [Freedom on the Net 2025](https://freedomhouse.org/country/russia/freedom-net/2025), сохранение старого сценария | ru/su/рф и category-ru; отдельно ru-blocked для выборочного VPN | runetfreedom geoip-ru; ru-ip-blocked для выборочного VPN |
| Китай | [Freedom on the Net 2025](https://freedomhouse.org/country/china/freedom-net/2025) | cn/中国/中國, SagerNet geosite-cn (в том числе выражения CDN) | SagerNet geoip-cn |
| Иран | [Freedom on the Net 2025](https://freedomhouse.org/country/iran/freedom-net/2025) | ir/ایران, Chocolate4U geosite-ir | SagerNet geoip-ir |
| Беларусь | [Freedom on the Net 2025](https://freedomhouse.org/country/belarus/freedom-net/2025) | by/бел | SagerNet geoip-by |
| Турция | [Freedom on the Net 2025](https://freedomhouse.org/country/turkey/freedom-net/2025) | tr | SagerNet geoip-tr |
| Вьетнам | [Freedom on the Net 2025](https://freedomhouse.org/country/vietnam/freedom-net/2025) | vn | SagerNet geoip-vn |
| Мьянма | [Freedom on the Net 2025](https://freedomhouse.org/country/myanmar/freedom-net/2025) | mm | SagerNet geoip-mm |
| Туркменистан | [Freedom in the World 2025: ограничения VPN](https://freedomhouse.org/country/turkmenistan/freedom-world/2025), [OONI](https://explorer.ooni.org/country/TM) | tm | SagerNet geoip-tm |

Freedom House и OONI используются для обоснования подбора стран, а не для генерации правил или автоматического определения блокировки. У OONI для Туркменистана ограниченное покрытие: число измерений не доказывает доступность/блокировку конкретного ресурса. Вне России не предлагается выдуманный универсальный список заблокированных сайтов. Полный туннель и свои правила доступны также через «Другую страну».

Точные URL и национальные доменные зоны находятся в `helmsman/regions.py`. Источники данных: [runetfreedom](https://github.com/runetfreedom/russia-v2ray-rules-dat), [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite), [SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip), [Chocolate4U](https://github.com/Chocolate4U/Iran-sing-box-rules). Все 13 URL отдали SRS, которые штатный sing-box 1.14.3 декомпилировал и принял. Списки скачиваются по запросу, их источники могут меняться независимо от Helmsman. Условия использования остаются у источников.

Для каждой страны предусмотрены полный туннель, местные домены напрямую, местные домены и IP напрямую и свои правила. В России IP-вариант — прежний ru-except, дополнительно сохранён ru-selective. Для Беларуси, Турции, Вьетнама, Мьянмы, Туркменистана доменное исключение ограничено национальной зоной, не всеми сайтами местных организаций. GeoIP может отправить напрямую сторонний сервис на местном CDN. Пользовательские исключения имеют приоритет.

Списки применяются в едином sing-box слое для обычных протоколов, WG/AWG и SOCKS-пути Xray. Xray остаётся транспортом; ZeroTier остаётся отдельной виртуальной LAN. В DNS проецируются только domain/domain_suffix/domain_regex, IP-списки проверяются маршрутизатором после resolve реального адреса. DNS выбранной страны не подставляется автоматически; работоспособность пользовательских DoH/DoT и bootstrap DNS зависит от сети.

При отсутствии кэша загрузить списки можно через текущий рабочий VPN с полным туннелем. Неуспешная первая загрузка не заменяет действующий пресет, ошибка обновления сохраняет прежний список. Native check и синтетические тесты не подтверждают доступность реального сервера или обход DPI/отключения интернета в любой из стран.
