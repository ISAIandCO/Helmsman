#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Запустите: sudo bash uninstall.sh [--purge]'; exit 1; }
purge=0
target_user=${SUDO_USER:-deck}
while (($#)); do
  case $1 in
    --purge) purge=1; shift ;;
    --user) target_user=${2:?}; shift 2 ;;
    *) echo "Неизвестный параметр: $1"; exit 1 ;;
  esac
done
[[ $target_user != root && $target_user =~ ^[a-z_][a-z0-9_-]*\$?$ ]] || exit 1
exec 9>/run/helmsman-install.lock
flock -n 9 || { echo 'Уже выполняется установка или удаление Helmsman'; exit 1; }
if [[ -x /opt/helmsman/current/Helmsman ]]; then
  /opt/helmsman/current/Helmsman ctl disconnect >/dev/null || true
fi
systemctl disable --now helmsman.service helmsman-guard.service 2>/dev/null || true
# Emergency cleanup also works if the service binary/config was damaged.
if nft list table inet helmsman_guard &>/dev/null; then nft delete table inet helmsman_guard; fi
rm -f /opt/helmsman/state/guard.json
for family in -4 -6; do
  for pref in {31800..31811}; do ip "$family" rule del pref "$pref" 2>/dev/null || true; done
  ip "$family" route flush table 31800 2>/dev/null || true
done
ip link del helmsman0 2>/dev/null || true
python3 - <<'PY'
import json,os,tempfile
from pathlib import Path
p = Path('/opt/helmsman/state/state.json')
if p.exists():
    try:
        data=json.loads(p.read_text());data['desired']=False
        fd,tmp=tempfile.mkstemp(dir=p.parent)
        with os.fdopen(fd,'w') as f: json.dump(data,f,ensure_ascii=False);f.flush();os.fsync(f.fileno())
        os.replace(tmp,p)
    except (ValueError,OSError):
        print('Файл настроек повреждён; сохранён для ручного восстановления.')

PY
rm -f /etc/systemd/system/helmsman.service /etc/systemd/system/helmsman-guard.service
systemctl daemon-reload
target_home=$(getent passwd "$target_user" | cut -d: -f6)
runuser -u "$target_user" -- rm -f -- "$target_home/.local/share/applications/helmsman.desktop" "$target_home/.local/bin/helmsman"
runuser -u "$target_user" -- rm -rf -- "$target_home/homebrew/plugins/helmsman"
systemctl try-restart plugin_loader.service || true
rm -rf -- /opt/helmsman/versions /opt/helmsman/current /opt/helmsman/current.new /opt/helmsman/current.rollback /var/lib/helmsman-app
if ((purge)); then
  rm -rf -- /opt/helmsman/state /var/lib/helmsman
fi
rmdir /opt/helmsman 2>/dev/null || true
echo 'Helmsman удалён, сетевые ресурсы освобождены. Без --purge настройки сохраняются.'
