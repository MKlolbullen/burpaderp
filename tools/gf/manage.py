#!/usr/bin/env python3
"""Generate, verify and install the curated offline GF packs (Python standard library only)."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / 'gf/catalog.json'
PACKS = ROOT / 'gf/packs'


def load_catalog():
    catalog = json.loads(CATALOG.read_text())
    if catalog['schemaVersion'] != 1:
        raise ValueError('Unsupported catalog schema')
    ids = set()
    for rule in catalog['rules']:
        if not re.fullmatch('[a-z0-9-]{1,100}', rule['id']) or rule['id'] in ids:
            raise ValueError('Invalid or duplicate rule ID')
        ids.add(rule['id'])
        if not rule['positive'] or not rule['negative']:
            raise ValueError('Every rule needs positive and negative fixtures')
        # Python's grammar check is additional validation; Java and grep are tested separately.
        re.compile(rule['pattern'], re.MULTILINE | (re.IGNORECASE if rule['ignoreCase'] else 0))
    return catalog


def rendered(catalog):
    groups = collections.defaultdict(list)
    variants = collections.defaultdict(set)
    for rule in catalog['rules']:
        groups[rule['pack'], rule['ignoreCase']].append(rule)
        variants[rule['pack']].add(rule['ignoreCase'])
    files = {}
    for (base, ci), rules in sorted(groups.items()):
        name = base + (('-ci' if ci else '-cs') if len(variants[base]) > 1 else '')
        rows = sorted(rules, key=lambda r: r['id'])
        metadata = [{k: r[k] for k in ('id', 'provider', 'category', 'severity', 'pattern', 'capture', 'minEntropy', 'validator', 'keywords', 'sources')} for r in rows]
        pack = {'flags': '-Pi' if ci else '-P', 'patterns': [r['pattern'] for r in rows],
                'reconhound': {'schemaVersion': 1, 'catalogVersion': catalog['catalogVersion'], 'rules': metadata}}
        files[name + '.json'] = json.dumps(pack, indent=2) + '\n'
    files['index.txt'] = '\n'.join(sorted(files)) + '\n'
    return files


def check_generated(files):
    stale = [name for name, text in files.items() if not (PACKS / name).is_file() or (PACKS / name).read_text() != text]
    stale += [p.name for p in PACKS.glob('rh-*.json') if p.name not in files]
    if stale:
        raise ValueError('Generated files are stale: ' + ', '.join(stale))


def atomic_write(path, content):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(content.encode())
    try:
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def install(files, target):
    packs = {n: text.encode('utf-8') for n, text in files.items() if n.endswith('.json')}
    selected = {'GITLEAKS-LICENSE.txt': (ROOT / 'gf/GITLEAKS-LICENSE.txt').read_bytes(), **packs}
    target = target.expanduser().absolute()
    if target.is_symlink():
        raise ValueError('Refusing a symlink as the installation directory')
    target.mkdir(parents=True, exist_ok=True)
    for name, content in selected.items():
        path = target / name
        if path.is_symlink() or (path.exists() and not identical_regular_file(path, content)):
            raise ValueError('Existing file preserved; move conflicting file first: ' + str(path))
    created = []
    try:
        for name, content in selected.items():
            path = target / name
            # Exclusive creation also preserves a file created after the preflight check.
            try:
                handle = path.open('xb')
            except FileExistsError:
                if not identical_regular_file(path, content):
                    raise ValueError('Concurrent change preserved: ' + str(path))
                continue
            with handle:
                identity = os.fstat(handle.fileno())
                created.append((path, identity.st_dev, identity.st_ino))
                handle.write(content)
    except BaseException:
        for path, device, inode in reversed(created):
            try:
                current = path.lstat()
                if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == (device, inode):
                    path.unlink()
            except OSError:
                pass  # Preserve the original error and any replacement owned by another writer.
        raise
    print(f'Installed {len(packs)} packs and Gitleaks notice in {target}; existing unrelated files preserved.')


def identical_regular_file(path, content):
    if path.is_symlink():
        return False
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as handle:
            return stat.S_ISREG(os.fstat(handle.fileno()).st_mode) and handle.read(len(content) + 1) == content
    except OSError:
        return False


def verify_grep(catalog):
    env = dict(os.environ, LC_ALL='C')
    for rule in catalog['rules']:
        for sample in rule['positive']:
            value = ''.join(sample['valueParts'])
            text = sample['prefix'] + value + sample['suffix']
            result = subprocess.run(['grep', '-Pi' if rule['ignoreCase'] else '-P', '--', rule['pattern']],
                                    input=text, text=True, capture_output=True, env=env, timeout=2)
            if result.returncode != 0:
                raise ValueError('grep positive/compile failure: ' + rule['id'])
        for sample in rule['negative']:
            if sample.get('nativeOnly'):
                continue
            text = ''.join(sample['parts'])
            result = subprocess.run(['grep', '-Pi' if rule['ignoreCase'] else '-P', '--', rule['pattern']],
                                    input=text, text=True, capture_output=True, env=env, timeout=2)
            if result.returncode != 1:
                raise ValueError('grep negative/compile failure: ' + rule['id'])
    # Exercise gf's actual array-combination behavior, not only individual expressions.
    for name, rendered_pack in rendered(catalog).items():
        if not name.endswith('.json'):
            continue
        pack = json.loads(rendered_pack)
        rule_ids = {r['id'] for r in pack['reconhound']['rules']}
        samples = [s for r in catalog['rules'] if r['id'] in rule_ids for s in r['positive']]
        text = '\n'.join(s['prefix'] + ''.join(s['valueParts']) + s['suffix'] for s in samples)
        expression = '(' + '|'.join(pack['patterns']) + ')'
        result = subprocess.run(['grep', pack['flags'], '--', expression], input=text, text=True,
                                capture_output=True, env=env, timeout=5)
        if result.returncode != 0 or any(''.join(s['valueParts']) not in result.stdout for s in samples):
            raise ValueError('Combined GF pack fixture/compile failure: ' + name)
    print(f"GNU grep fixtures passed for {len(catalog['rules'])} rules. Native-only validators/entropy are tested by Java.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('generate', 'check', 'install', 'test-grep'))
    home = Path.home()
    default = home / ('.config/gf' if (home / '.config/gf').is_dir() else '.gf')
    parser.add_argument('--directory', type=Path, default=default)
    args = parser.parse_args(argv)
    catalog = load_catalog()
    files = rendered(catalog)
    if args.command == 'generate':
        PACKS.mkdir(parents=True, exist_ok=True)
        for obsolete in PACKS.glob('rh-*.json'):
            if obsolete.name not in files:
                old = json.loads(obsolete.read_text())
                if old.get('reconhound', {}).get('schemaVersion') != 1:
                    raise ValueError('Unrecognized file preserved: ' + str(obsolete))
                obsolete.unlink()
        for name, text in files.items():
            atomic_write(PACKS / name, text)
        print(f"Generated {len(files)-1} packs / {len(catalog['rules'])} rules.")
    elif args.command == 'check':
        check_generated(files)
        print(f"Catalog and {len(files)-1} generated packs agree.")
    elif args.command == 'test-grep':
        check_generated(files)
        verify_grep(catalog)
    else:
        check_generated(files)
        install(files, args.directory)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
