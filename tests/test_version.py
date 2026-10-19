"""Changing the sole source must change the version reported on the next launch."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class VersionTests(unittest.TestCase):
    def test_restart_reads_changed_root_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'helmsman'; package.mkdir()
            for name in ('__init__.py', 'common.py', 'regions.py'):
                shutil.copy2(ROOT / 'helmsman' / name, package / name)
            for value in ('9.8.7', '9.8.8-rc.1'):
                (root / 'VERSION').write_text(value + '\n')
                command = 'import sys; sys.path.insert(0, sys.argv[1]); from helmsman.common import VERSION; print(VERSION)'
                result = subprocess.check_output([sys.executable, '-I', '-c', command, directory], text=True)
                self.assertEqual(result.strip(), value)
