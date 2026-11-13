# SPDX-License-Identifier: BSD-2-Clause
"""Check the independently identifiable inputs and candidate before execution."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    source_root = args.root.resolve()
    manifest = json.loads((source_root / 'SOURCE_MANIFEST.json').read_text())
    assert manifest['schema'] == 'safe-freeze-source-manifest.v1'
    for name, expected in manifest['files'].items():
        path = source_root / name
        assert path.is_file() and not path.is_symlink(), name
        assert path.resolve().is_relative_to(source_root), name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, name
    authorization = json.loads((source_root / manifest.get('authorization_path', 'reports/license-authorization.json')).read_text())
    assert authorization['status'] == 'OWNER_AUTHORIZED_BSD_2_CLAUSE'
    assert authorization['original_inputs_rewritten'] is False
    assert (source_root / manifest.get('candidate_root', 'candidate') / 'include/MinHook.h').read_bytes() == (source_root / manifest.get('official_root', 'inputs/official') / 'include/MinHook.h').read_bytes()
    assert (source_root / manifest.get('candidate_root', 'candidate') / 'dll_resources/MinHook.def').read_bytes() == (source_root / manifest.get('official_root', 'inputs/official') / 'dll_resources/MinHook.def').read_bytes()
    if manifest.get('contribution_commit'):
        for name in manifest['contribution_inputs']:
            expected = subprocess.check_output(['git', '-C', str(source_root), 'rev-parse',
                                               manifest['contribution_commit'] + ':' + name], text=True).strip()
            actual = subprocess.check_output(['git', '-C', str(source_root), 'hash-object',
                                             '--no-filters', name], text=True).strip()
            assert actual == expected, 'Contribution input differs: ' + name
    subprocess.run([sys.executable, '-B', str(source_root / 'tests/safe_freeze/check_default_sources.py'),
                    '--root', str(source_root), '--official-root',
                    str(source_root / manifest.get('official_root', 'inputs/official'))], check=True)
    print(json.dumps({'result': 'PASS', 'files': len(manifest['files']),
                      'licensing_basis': authorization['status'], 'abi_header_and_exports': 'UNCHANGED'}))


if __name__ == '__main__':
    main()
