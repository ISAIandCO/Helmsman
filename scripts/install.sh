#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID != 0 ]]; then echo 'Запустите: sudo bash install.sh [--decky]'; exit 1; fi
target_user=${SUDO_USER:-deck}
decky=0
while (($#)); do
  case $1 in
    --decky) decky=1; shift ;;
    --user) target_user=${2:?Нужно имя пользователя}; shift 2 ;;
    *) echo "Неизвестный параметр: $1"; exit 1 ;;
  esac
done
[[ $target_user != root && $target_user =~ ^[a-z_][a-z0-9_-]*\$?$ ]] || { echo 'Укажите обычного пользователя через --user'; exit 1; }
target_uid=$(id -u "$target_user")
target_home=$(getent passwd "$target_user" | cut -d: -f6)
for tool in systemctl nft ip setpriv runuser python3 ldd; do
  command -v "$tool" >/dev/null || { echo "Отсутствует системный компонент: $tool"; exit 1; }
done
[[ -c /dev/net/tun ]] || { echo 'Недоступен /dev/net/tun'; exit 1; }
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ -x $source_dir/app/Helmsman && -x $source_dir/app/engines/sing-box && -x $source_dir/app/engines/sing-box-awg && -x $source_dir/app/engines/zerotier-one && -x $source_dir/app/engines/xray && -x $source_dir/app/engines/wgcf ]] || { echo 'Нужен полный распакованный архив релиза'; exit 1; }
for library in "$source_dir"/app/_internal/libpython*.so* "$source_dir"/app/_internal/PySide6/Qt/lib/libQt6{Core,Gui,Widgets,Network}.so.6 "$source_dir"/app/_internal/PySide6/Qt/plugins/platforms/libqxcb.so "$source_dir"/app/engines/zerotier-one; do
  missing=$(LC_ALL=C ldd "$library" | awk '/not found/{print $1}')
  [[ -z $missing ]] || { echo "Отсутствуют системные библиотеки для $(basename "$library"): $missing"; exit 1; }
done
version=$(cat "$source_dir/VERSION")
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?$ ]] || exit 1
id helmsman-engine &>/dev/null || useradd --system --no-create-home --shell /usr/bin/nologin helmsman-engine
install -d -m 0755 /var/lib/helmsman-app /var/lib/helmsman-app/versions
install -d -m 0711 /var/lib/helmsman
destination=/var/lib/helmsman-app/versions/$version
[[ ! -L $destination ]] || { echo 'Некорректный каталог установленной версии'; exit 1; }
staging=$(mktemp -d /var/lib/helmsman-app/versions/.install-XXXXXXXX)
trap 'rm -rf -- "$staging"' EXIT
cp -a -- "$source_dir/app/." "$staging/"
chown -R root:root "$staging"
chmod -R go-w "$staging"
chmod 0755 "$staging"
old=$(readlink /var/lib/helmsman-app/current || true)
systemctl stop helmsman.service 2>/dev/null || true
if [[ -e $destination ]]; then
  # Never overwrite the image still used by an old Qt/daemon process.
  destination=$destination-$(date +%s)
fi
mv -- "$staging" "$destination"
ln -s "$destination" /var/lib/helmsman-app/current.new
mv -Tf /var/lib/helmsman-app/current.new /var/lib/helmsman-app/current
sed "s/@UID@/$target_uid/g" "$source_dir/packaging/helmsman.service.in" > /etc/systemd/system/helmsman.service
install -m 0644 "$source_dir/packaging/helmsman-guard.service" /etc/systemd/system/helmsman-guard.service
systemctl daemon-reload
systemctl enable helmsman-guard.service helmsman.service
ready=0
if systemctl restart helmsman-guard.service helmsman.service; then
  for attempt in {1..20}; do
    if /var/lib/helmsman-app/current/Helmsman ctl status >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.5
  done
fi
if (( ! ready )); then
  if [[ -n $old && -d $old ]]; then
    ln -s "$old" /var/lib/helmsman-app/current.rollback
    mv -Tf /var/lib/helmsman-app/current.rollback /var/lib/helmsman-app/current
    systemctl restart helmsman.service || true
  fi
  echo 'Сервис не запустился. Предыдущая версия восстановлена, если была. Выполните journalctl -u helmsman -b.'
  exit 1
fi
runuser -u "$target_user" -- mkdir -p "$target_home/.local/share/applications" "$target_home/.local/bin"
runuser -u "$target_user" -- install -m 0644 "$source_dir/packaging/helmsman.desktop" "$target_home/.local/share/applications/helmsman.desktop"
runuser -u "$target_user" -- ln -sfn /var/lib/helmsman-app/current/Helmsman "$target_home/.local/bin/helmsman"
if ((decky)); then
  [[ -d $target_home/homebrew/plugins ]] || { echo 'Приложение установлено. Сначала установите Decky Loader, затем повторите с --decky.'; exit 1; }
  runuser -u "$target_user" -- mkdir -p "$target_home/homebrew/plugins/helmsman"
  runuser -u "$target_user" -- cp -R -- "$source_dir/decky/." "$target_home/homebrew/plugins/helmsman/"
  systemctl try-restart plugin_loader.service || true
fi
echo 'Helmsman установлен. Откройте его в меню приложений → Интернет. Настройки сохранены.'
