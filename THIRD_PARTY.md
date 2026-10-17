# Компоненты и лицензии

Helmsman: GPL-3.0-only, см. LICENSE. Компоненты запускаются отдельными процессами; сетевые протоколы и криптография не реализуются в Helmsman.

| Компонент | Закрепление | Лицензия / распространение |
|---|---|---|
| SagerNet/sing-box | 1.14.3, 7054cac5124465ffdb145870d7c01885566711b1 | GPL-3.0 с upstream notices; отдельный бинарник, полный vendored source archive |
| Throne/sing-box | 8b3b24f856bd875b88c27c40a17a8f8fb5e02718 | GPL-3.0, включает закреплённые Throne/wireguard-go и Throne/sing, исходники/уведомления сохраняются |
| ZeroTier Agent | 1.16.2, 899352e38405968516bb12a770f0ac02f6058fa8 | MPL-2.0 для Agent; без nonfree controller, без SSO. Nonfree-код не компилируется и не поставляется в архиве исходников |
| Qt / PySide6 / Shiboken6 | 6.9.3 | LGPL-3.0/GPL и лицензии Qt-модулей по upstream notices; динамические библиотеки доступны для замены. Используются QtCore/Gui/Widgets/Network; Qt Addons не импортируются |
| CPython | 3.12.12 в CI | PSF License; runtime в PyInstaller bundle |
| PyInstaller | 6.16.0 | GPL-2.0 с исключением для bootloader; приложение сохраняет свою лицензию |
| @decky/api, @decky/ui, @decky/rollup | package-lock.json | BSD-3-Clause и соответствующие notices зависимостей; runtime React предоставляется Decky, не копируется |
| Go modules / npm build dependencies | go.sum + vendor / package-lock.json | Их собственные лицензии, сохранены в исходниках и/или app/licenses |

Оба sing-box собираются с небольшой открытой правкой `patches/sing-box-doh-query.patch`: query-параметры частного DoH URL передаются как параметры, а не часть пути. Изменённый файл помечен датой; SHA256 правки записан в BUILD.json/HELMSMAN-REVISION.json, изменённые исходники входят в engine-sources. Остальные сетевые реализации взяты из закреплённых upstream commits.

В `app/licenses` собраны upstream LICENSE/COPYING/NOTICE из движков и vendored зависимостей. Исходники используемых Qt-модулей, PySide6/Shiboken, CPython и PyInstaller включены в отдельный runtime-sources архив релиза; уведомления скопированы из этих исходников. Исходники Qt 6.9.3 также доступны в [официальном архиве Qt](https://download.qt.io/archive/qt/6.9/6.9.3/), PySide — в [qt-for-python](https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.9.3-src/). Пользователь может пересобрать и заменить динамические библиотеки; механизма запрета модификаций нет.

Вдохновение от NekoBox_SF, Throne, Hiddify и AmneziaVPN не означает копирование их интерфейсов или включение всех их возможностей. Самостоятельно получаемые российские списки сохраняют условия своего источника; они не встроены в бинарники и не выдаются за официальные сведения.
