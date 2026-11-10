# SPDX-License-Identifier: BSD-2-Clause
"""Bounded, isolated executable runs; keep every failure, never auto-retry."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def execute(binary, arguments, directory, wine):
    executable = binary.resolve()
    if not executable.is_file():
        raise FileNotFoundError(executable)
    directory.mkdir(parents=True, exist_ok=False)
    command = [str(executable), *map(str, arguments)]
    if wine:
        command = [sys.executable, '-B', str(ROOT / 'tools/wine_runner.py'),
                   '--timeout', '120', wine, *command]
    started = time.monotonic()
    try:
        with (directory / 'combined.log').open('wb') as log:
            process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                     timeout=130, check=False)
        code = process.returncode
    except subprocess.TimeoutExpired:
        code = 124
    output = (directory / 'combined.log').read_text(errors='replace')
    result = {'command': command, 'exit_code': code, 'seconds': time.monotonic() - started,
              'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
              'log': str((directory / 'combined.log').resolve().relative_to(ROOT)), 'metrics': None}
    for line in output.splitlines():
        if line.startswith('{'):
            result['metrics'] = json.loads(line)
    (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--wine', help='Wine executable: results are explicitly not native Windows')
    parser.add_argument('--samples', type=int, default=200, choices=range(1, 1001))
    parser.add_argument('--matrix', action='store_true')
    parser.add_argument('--stress', action='store_true')
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    if not args.wine and os.name != 'nt':
        parser.error('Native execution requires Windows; select --wine for separate compatibility evidence')
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = 'wine-compatibility-not-native' if args.wine else 'windows-native'
    rows = []
    cases = [('failure_injection', []), ('real_peer', [])]
    if args.matrix:
        for variant, method in [('official', 0), ('candidate_default', 0), ('candidate_strict', 0),
                                ('comparison', 0), ('comparison', 1), ('comparison', 2)]:
            for threads in [1, 4, 16, 32, 64]:
                for hooks in [1, 4, 11]:
                    cases.append(('workload_' + variant, [threads, hooks, args.samples, method]))
    if args.stress:
        for scenario in ['steady', 'churn', 'held', 'abort']:
            cases.append(('workload_candidate_strict', [16, 11, args.samples, 0, scenario]))
        for _ in range(20):
            cases.append(('failure_injection', []))
    for index, (name, arguments) in enumerate(cases):
        print(f'[{index + 1}/{len(cases)}] {name} {arguments}', flush=True)
        result = execute(args.build / (name + '.exe'), arguments,
                         args.output / f'{index:03d}-{name}', args.wine)
        rows.append(result)
        # Continue collecting independently isolated failures, without retrying.
    controls = []
    if args.controls:
        definitions = [('real_peer_official', 42, ['SINGLE_DISABLE_IP_MISMATCH', 'REAL_PEER_CLEANUP: PASS']),
                       ('recovery_control_apply', 1, ['FAIL: no-op apply must not hide unresolved owner']),
                       ('recovery_control_remove', 1, ['FAIL: disabled removal cannot retire trampoline under unresolved ownership'])]
        for name, expected, markers in definitions:
            result = execute(args.build / (name + '.exe'), [], args.output / name, args.wine)
            output = (ROOT / result['log']).read_text(errors='replace')
            result.update(expected_exit=expected, expected_markers=markers,
                          control_pass=result['exit_code'] == expected and all(m in output for m in markers))
            controls.append(result)
    report = {'evidence_class': evidence, 'samples_requested': args.samples,
              'unsafe_comparison_note': 'comparison method 2 does not freeze or relocate; not safety-equivalent',
              'peak_note': 'Handle/memory peaks are observations, not continuous high-water guarantees',
              'cases': rows, 'negative_controls': controls,
              'result': 'PASS' if all(r['exit_code'] == 0 for r in rows) and all(r['control_pass'] for r in controls) else 'FAIL'}
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'result': report['result'], 'evidence_class': evidence,
                      'cases': len(rows), 'failed': sum(r['exit_code'] != 0 for r in rows),
                      'negative_controls': len(controls),
                      'failed_controls': sum(not r['control_pass'] for r in controls)}))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
