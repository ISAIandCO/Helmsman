Helmsman 0.1.0-alpha.2 для Steam Deck.

- XHTTP через официальный Xray-core: VLESS/VMess/Trojan, auto/packet-up/stream-up/stream-one, TLS/REALITY, padding/xmux/downloadSettings, TCP и UDP. Сохраняются общий TUN, DNS, правила и защита при обрыве.
- WARP с маскировкой AmneziaWG: импорт warpgen .conf с I1/junk-параметрами, Reserved и распространённых WireGuard JSON-экспортов.
- Генератор WARP в Desktop и Decky: AmneziaWG по умолчанию, обычный WireGuard по выбору, свой endpoint, явное согласие с условиями Cloudflare и повторное использование приватной учётной записи.
- Исправлен импорт .conf с комментариями перед [Interface]. Ключи/токены генератора не выводятся в диагностику.
- Сохранены раздельные пользовательские DoH/DoT и готовые DNS-провайдеры, подписки/HWID, российские пресеты, ZeroTier и остальные протоколы.

Установка/обновление: скачайте linux-x86_64.tar.gz и SHA256SUMS, проверьте сумму, распакуйте и выполните `sudo bash install.sh --decky` в Desktop Mode. Настройки и аккаунт WARP сохраняются. Для первого подключения откройте Helmsman в меню приложений → Интернет.

Подробная матрица и проверки — README, docs/COMPATIBILITY.md и docs/TESTING.md. Физический Steam Deck, регистрация/подключение Cloudflare WARP и внешние провайдеры требуют отдельной проверки. MASQUE/Zero Trust enrolment, VLESS encryption, Amnezia API/Gateway и параллельные VPN не реализованы. Генератор может быть недоступен из-за ограничений Cloudflare/сети; готовый профиль можно импортировать.

Decky zip требует сервис из полного пакета. Архивы source/engine-sources/runtime-sources и BUILD.json содержат соответствующие исходники, лицензии и закрепления сборки.
