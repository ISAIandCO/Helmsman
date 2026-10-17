"""Prepare private, root-owned storage on the installation filesystem."""
import shutil
import subprocess
import sys
from pathlib import Path

MIB = 1024 * 1024


def secure_directory(path, mode=0o755):
    if path.is_symlink():
        raise RuntimeError('Каталог хранения не должен быть ссылкой: ' + str(path))
    path.mkdir(mode=mode, exist_ok=True)
    st = path.stat()
    if not path.is_dir() or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('Нужен каталог root без записи для других пользователей: ' + str(path))


def prepare(package, base=Path('/opt/helmsman')):
    base = Path(base)
    secure_directory(base.parent)
    secure_directory(base)
    secure_directory(base / 'versions')
    secure_directory(base / 'state', 0o711)
    # The installer holds its lock: these are abandoned partial copies only.
    for item in (base / 'versions').glob('.install-*'):
        if item.is_symlink():
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)
    needed = int(subprocess.check_output(['du', '-s', '-B1', str(package)], text=True).split()[0])
    needed += max(64 * MIB, needed // 20)
    free = shutil.disk_usage(base).free
    if free < needed:
        raise RuntimeError(f'Недостаточно места на {base}: нужно {(needed + MIB - 1) // MIB} МиБ, доступно {free // MIB} МиБ. Освободите место на этом разделе; текущая установка и настройки сохранены.')
    print(f'Хранилище {base}: требуется {(needed + MIB - 1) // MIB} МиБ, свободно {free // MIB} МиБ.', flush=True)
    return base


if __name__ == '__main__':
    try:
        prepare(sys.argv[1])
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('Helmsman: ' + str(error), file=sys.stderr)
        sys.exit(1)
