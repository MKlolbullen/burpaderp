import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('gf_manage', Path(__file__).resolve().parents[1] / 'manage.py')
MANAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MANAGE)

class ManageTests(unittest.TestCase):
    def test_generated_outputs_match_catalog_and_every_rule_has_provenance_and_fixtures(self):
        catalog = MANAGE.load_catalog()
        MANAGE.check_generated(MANAGE.rendered(catalog))
        for rule in catalog['rules']:
            self.assertTrue(rule['sources'])
            self.assertTrue(rule['positive'])
            self.assertTrue(rule['negative'])

    def test_install_is_idempotent_and_preserves_unrelated_packs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unrelated = root / 'xss.json'
            unrelated.write_text('{"pattern":"user-owned"}')
            files = MANAGE.rendered(MANAGE.load_catalog())
            MANAGE.install(files, root)
            MANAGE.install(files, root)
            self.assertEqual(unrelated.read_text(), '{"pattern":"user-owned"}')
            self.assertEqual(len(list(root.glob('rh-*.json'))), len(files)-1)
            self.assertEqual((root/'GITLEAKS-LICENSE.txt').read_bytes(),
                             (MANAGE.ROOT/'gf/GITLEAKS-LICENSE.txt').read_bytes())

    def test_conflicting_notice_and_notice_symlink_abort_before_copying_packs(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                notice = root/'GITLEAKS-LICENSE.txt'
                if symlink:
                    target = root/'user-notice.txt'
                    target.write_bytes((MANAGE.ROOT/'gf/GITLEAKS-LICENSE.txt').read_bytes())
                    notice.symlink_to(target)
                else:
                    notice.write_text('user-owned notice')
                original = notice.read_bytes()
                with self.assertRaises(ValueError):
                    MANAGE.install({'rh-first.json':'{"pattern":"first"}'}, root)
                self.assertFalse((root/'rh-first.json').exists())
                self.assertEqual(notice.read_bytes(), original)
                self.assertEqual(notice.is_symlink(), symlink)

    def test_conflicting_pack_and_symlinks_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {'rh-first.json':'{"pattern":"first"}', 'rh-second.json':'{"pattern":"second"}'}
            conflict = root / 'rh-second.json'
            conflict.write_text('user-changed')
            with self.assertRaises(ValueError):
                MANAGE.install(files, root)
            self.assertEqual(conflict.read_text(), 'user-changed')
            self.assertFalse((root/'rh-first.json').exists())
            conflict.unlink()
            target = root/'untouched'
            target.write_text('keep')
            conflict.symlink_to(target)
            with self.assertRaises(ValueError):
                MANAGE.install(files, root)
            self.assertEqual(target.read_text(), 'keep')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO fixture')
    def test_fifo_destinations_fail_without_blocking_or_copying_files(self):
        for name in ('GITLEAKS-LICENSE.txt', 'rh-auth-cs.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                os.mkfifo(root/name)
                result = subprocess.run([sys.executable, str(SPEC.origin), 'install', '--directory', str(root)],
                                        capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('Existing file preserved', result.stderr)
                self.assertFalse(any(path.is_file() for path in root.iterdir()))

    def test_partial_write_failure_or_interrupt_removes_only_new_files(self):
        real_open = Path.open
        class FailingWriter:
            def __init__(self, handle, error): self.handle, self.error = handle, error
            def __enter__(self): return self
            def __exit__(self, *args): self.handle.close()
            def fileno(self): return self.handle.fileno()
            def write(self, content):
                self.handle.write(content[:4])
                self.handle.flush()
                raise self.error('synthetic write interruption')
        for error in (OSError, KeyboardInterrupt):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                notice = root/'GITLEAKS-LICENSE.txt'
                notice.write_bytes((MANAGE.ROOT/'gf/GITLEAKS-LICENSE.txt').read_bytes())
                existing = root/'rh-existing.json'
                existing.write_text('existing identical pack')
                files = {'rh-existing.json':existing.read_text(), 'rh-new.json':'new pack', 'rh-fail.json':'failed pack'}
                def interrupted_open(path, mode='r', *args, **kwargs):
                    handle = real_open(path, mode, *args, **kwargs)
                    return FailingWriter(handle, error) if path.name == 'rh-fail.json' and mode == 'xb' else handle
                with mock.patch.object(Path, 'open', interrupted_open), self.assertRaises(error):
                    MANAGE.install(files, root)
                self.assertEqual(existing.read_text(), 'existing identical pack')
                self.assertEqual(notice.read_bytes(), (MANAGE.ROOT/'gf/GITLEAKS-LICENSE.txt').read_bytes())
                self.assertFalse((root/'rh-new.json').exists())
                self.assertFalse((root/'rh-fail.json').exists())

    def test_concurrent_conflict_rolls_back_new_files_and_preserves_the_other_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_open = Path.open
            def conflicting_open(path, mode='r', *args, **kwargs):
                if path.name == 'rh-second.json' and mode == 'xb':
                    with real_open(path, 'w') as handle:
                        handle.write('concurrent user file')
                    raise FileExistsError('synthetic concurrent creation')
                return real_open(path, mode, *args, **kwargs)
            with mock.patch.object(Path, 'open', conflicting_open), self.assertRaises(ValueError):
                MANAGE.install({'rh-first.json':'first', 'rh-second.json':'second'}, root)
            self.assertEqual((root/'rh-second.json').read_text(), 'concurrent user file')
            self.assertFalse((root/'rh-first.json').exists())
            self.assertFalse((root/'GITLEAKS-LICENSE.txt').exists())
