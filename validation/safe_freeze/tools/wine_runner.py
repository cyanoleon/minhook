# SPDX-License-Identifier: BSD-2-Clause

"""Capture Wine output without waiting for unrelated services' inherited pipes.

Use as CMAKE_CROSSCOMPILING_EMULATOR: python;this_script;wine64. The actual
Wine program's exit/timeout remains authoritative; a printed PASS is never used
to decide success. This helper does not change native Windows execution.
"""
import argparse
import math
import subprocess
import sys
import tempfile


def run(command, timeout):
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            code = 124
        except BaseException:
            process.kill()
            process.wait()
            raise
        # A Wine service may inherit this file descriptor. It cannot keep our
        # stdout pipe open; read only the bytes present when the program exited.
        output.seek(0, 2)
        size = output.tell()
        output.seek(0)
        sys.stdout.buffer.write(output.read(size))
        sys.stdout.flush()
        print('WINE_PROGRAM_EXIT=' + str(code), flush=True)
        return code if code >= 0 else 128 - code


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('Provide a positive timeout and wine64 plus the test program')
    try:
        raise SystemExit(run(args.command, args.timeout))
    except OSError as error:
        print('Wine test runner: ' + str(error), file=sys.stderr)
        raise SystemExit(127)
