"""Root storage and real bounded-filesystem regressions; mandatory in CI."""
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('helmsman_storage', ROOT / 'packaging/storage.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.opt = self.root / 'opt'
        self.var = self.root / 'var'
        self.opt.mkdir(); self.var.mkdir()
        self.package = self.root / 'package'
        self.package.mkdir()
        (self.package / 'payload').write_bytes(b'x' * 8192)
        self.mounts = []

    def tearDown(self):
        for path in reversed(self.mounts):
            subprocess.run(['umount', str(path)], check=True)
        self.tmp.cleanup()

    def mount(self, path, size):
        result = subprocess.run(['mount', '-t', 'tmpfs', '-o', f'size={size}', 'tmpfs', str(path)], capture_output=True)
        if result.returncode:
            if os.environ.get('HELMSMAN_CI'):
                self.fail('CI must allow the actual limited-filesystem regression: ' + result.stderr.decode())
            self.skipTest('Sandbox lacks CAP_SYS_ADMIN; required in GitHub CI')
        self.mounts.append(path)

    def test_direct_layout_retry_preserves_private_state(self):
        base = module.prepare(self.package, self.opt / 'helmsman')
        self.assertFalse(base.is_symlink())
        self.assertEqual((base / 'state').stat().st_mode & 0o777, 0o711)
        account = base / 'state/account.toml'
        account.write_text('test-only-private-account')
        account.chmod(0o600)
        abandoned = base / 'versions/.install-abandoned'
        abandoned.mkdir(); (abandoned / 'partial').write_bytes(b'x' * 8192)
        module.prepare(self.package, self.opt / 'helmsman')
        self.assertFalse(abandoned.exists())
        self.assertEqual(account.read_text(), 'test-only-private-account')
        self.assertEqual(account.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.var.iterdir()), [])

    def test_reject_writable_parent_and_redirected_versions(self):
        self.opt.chmod(0o777)
        with self.assertRaises(RuntimeError):
            module.prepare(self.package, self.opt / 'helmsman')
        self.opt.chmod(0o755)
        base = module.prepare(self.package, self.opt / 'helmsman')
        shutil.rmtree(base / 'versions')
        (base / 'versions').symlink_to(self.package)
        with self.assertRaises(RuntimeError):
            module.prepare(self.package, self.opt / 'helmsman')
        self.assertTrue((self.package / 'payload').exists())

    def test_full_install_filesystem_preserves_current_version_and_settings(self):
        self.mount(self.opt, '8M')
        base = self.opt / 'helmsman'
        image = base / 'versions/old'
        image.mkdir(parents=True)
        (base / 'current').symlink_to(image)
        state = base / 'state'
        state.mkdir(mode=0o711)
        (state / 'state.json').write_text('{"hwid":"persistent"}')
        with self.assertRaisesRegex(RuntimeError, 'Недостаточно места'):
            module.prepare(self.package, self.opt / 'helmsman')
        self.assertEqual((state / 'state.json').read_text(), '{"hwid":"persistent"}')
        self.assertEqual((base / 'current').resolve(), image)

    def test_real_package_does_not_consume_small_var(self):
        self.mount(self.var, '16M')
        package = ROOT / 'build' / ('helmsman-' + (ROOT / 'VERSION').read_text().strip()) / 'app'
        if not package.exists():
            if os.environ.get('HELMSMAN_CI'):
                self.fail('Build the installable package before running this test')
            self.skipTest('Requires the built application; mandatory in CI')
        before = shutil.disk_usage(self.var).free
        base = module.prepare(package, self.opt / 'helmsman')
        image = base / 'versions/new'
        image.mkdir()
        subprocess.run(['cp', '-a', str(package) + '/.', str(image)], check=True)
        (base / 'state/cache-fixture').write_bytes(b'x' * (20 * module.MIB))
        self.assertEqual(shutil.disk_usage(self.var).free, before)
        self.assertEqual(list(self.var.iterdir()), [])
        self.assertGreater(int(subprocess.check_output(['du', '-s', '-B1', str(image)], text=True).split()[0]), 16 * module.MIB)
        print('PASS real package and state use opt, leaving the 16 MiB var filesystem untouched', flush=True)


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('Run this storage test as root')
    unittest.main(verbosity=2)
