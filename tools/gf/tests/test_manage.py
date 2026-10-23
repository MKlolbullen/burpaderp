import importlib.util
from pathlib import Path
import tempfile
import unittest

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
