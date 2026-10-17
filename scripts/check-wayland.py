"""Launch the packaged GUI on a real headless Wayland compositor in CI."""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

out = Path('test-results')
out.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='helmsman-wayland-') as directory:
    os.chmod(directory, 0o700)
    env = {**os.environ, 'XDG_RUNTIME_DIR': directory, 'WAYLAND_DISPLAY': 'helmsman-qa',
           'XDG_SESSION_TYPE': 'wayland', 'QT_OPENGL': 'software'}
    env.pop('DISPLAY', None)
    env.pop('QT_QPA_PLATFORM', None)  # Exercise the application's automatic selection.
    log = out / 'weston.log'
    compositor = subprocess.Popen(['weston', '--backend=headless-backend.so', '--use-pixman',
                                  '--width=1280', '--height=800', '--socket=helmsman-qa',
                                  '--idle-time=0', '--no-config', '--log=' + str(log.resolve())],
                                 env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 8
        while not (Path(directory) / 'helmsman-qa').exists():
            if compositor.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(log.read_text() if log.exists() else 'Weston failed to start')
            time.sleep(0.05)
        result = subprocess.run([str(Path(sys.argv[1]).resolve()), '--smoke-test'],
                                env=env, capture_output=True, text=True, timeout=15)
        (out / 'wayland-client.log').write_text(result.stdout + result.stderr)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'Helmsman Qt platform: wayland' in result.stdout, result.stdout + result.stderr
        print('PASS packaged GUI uses native Wayland on Weston headless at 1280x800')
    finally:
        compositor.terminate()
        try:
            compositor.wait(timeout=5)
        except subprocess.TimeoutExpired:
            compositor.kill()
            compositor.wait()
