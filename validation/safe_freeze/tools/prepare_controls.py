# SPDX-License-Identifier: BSD-2-Clause
"""Create two isolated negative controls; never alter candidate or upstream."""
from pathlib import Path
import argparse
import shutil

ROOT = Path(__file__).resolve().parents[1]
GUARD = '''    if (g_hHeap != NULL && !RetryRetainedThreadOwnership())
    {
        LeaveSpinLock();
        return MH_ERROR_MEMORY_PROTECT;
    }'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-root', type=Path, default=ROOT / 'candidate')
    args = parser.parse_args()
    candidate_root = args.candidate_root.resolve()
    text = (candidate_root / 'src/hook.c').read_text(encoding='utf-8-sig')
    signatures = {'apply': 'MH_STATUS WINAPI MH_ApplyQueued(VOID)',
                  'remove': 'MH_STATUS WINAPI MH_RemoveHook(LPVOID pTarget)'}
    for name, signature in signatures.items():
        directory = ROOT / 'build/test-controls' / name
        directory.mkdir(parents=True, exist_ok=False)
        (directory / 'src').mkdir()
        shutil.copytree(candidate_root / 'include', directory / 'include')
        start = text.index(signature)
        position = text.index(GUARD, start)
        altered = text[:position] + text[position:].replace(GUARD, '', 1)
        (directory / 'src/hook.c').write_text(altered)
    print('PASS: two isolated single-guard controls prepared under build/')


if __name__ == '__main__':
    main()
