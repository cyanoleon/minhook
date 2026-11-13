# x64 relocator hardening results

Code revision: `3c7c88ca220d9105cd45edf69153e7e5a310bc3c`.
Native validation revision: `89379b862d6302f50a38ca665b5959b0b86c5e2a`.
[Native run 43390466258](https://github.com/cyanoleon/minhook/actions/runs/43390466258).

This development branch extends the existing strict-freeze engine with common
relocator fixes in both strict modes. It is separate from upstream PR #179;
that PR retains its existing contribution branch and measurements.
`BENCHMARK_RESULTS.md` records the earlier code revision, not this branch's
current compiled relocator.

## Correctness changes

- Reject a RIP-relative displacement that cannot be represented as signed
  32 bits; preserve address-size-prefixed EIP arithmetic modulo 32 bits.
- Require the legacy 0F opcode map before rewriting a long conditional branch;
  VEX memory instructions such as VPMASKMOVD retain their original encoding.
- Read code and padding through bounded VirtualQuery/ReadProcessMemory copies.
  Initialize unreadable scratch bytes and reject truncated instructions.
- Reject decoder-marked relative instructions without a relocation rule,
  including XBEGIN, rather than copying a stale relative destination.

MSVC x64 Debug/Release and ClangCL x64 Release each passed all six standalone
CTest entries. The new entry performs 60,019 assertions, including 20,000
deterministically generated MOV-immediate and VPMASKMOVD load/store examples,
slot-boundary canaries, range/wrapping checks, an inaccessible trailing page,
unsupported-relative refusal and real CPU original/trampoline call-through.
This is a bounded corpus, not exhaustive instruction or differential fuzzing.
No AVX instruction is executed by the corpus, so AVX hardware is not required.

The three x64 cells also passed 183 isolated positive child executions and nine
precise expected-failure controls, alongside six actual PE export checks across
strict ON/OFF shared DLLs. Downloaded child binary hashes, archived source
members, all 25 contribution input pins and PE exports were independently
verified. Two resource inputs are verified against the Git contribution revision
and manifest; they are not included in these downloaded source archives.

## Current x64 measurements

Release, 64 owned workers, eleven hooks, five warmups and 200 timed samples.
Values are microseconds. Workers wait on an event; the timed benchmark does not
execute target/trampoline code. This measures engine lifecycle operations,
not per-hook-call overhead, FPS or application callback-drain/unload duration.
The 64 workers oversubscribe four logical processors.

Current host: AMD EPYC 9V74 80-Core Processor; four logical processors,
MSVC 19.44, Windows kernel 10.0.20348.

| Implementation / mode | Create eleven median | Queued enable median | Queued enable p95 | Uninitialize median |
| --- | ---: | ---: | ---: | ---: |
| Official | 30.70 | 10990.45 | 11826.10 | 13.60 |
| Hardened, strict OFF | 64.40 | 8342.45 | 8866.00 | 16.90 |
| Hardened, strict ON | 53.70 | 1831.80 | 2206.00 | 2141.00 |
| m417z MinHook original | 32.40 | 21197.20 | 24752.70 | 14.60 |
| m417z fast-undocumented | 28.60 | 15203.20 | 15437.40 | 22.95 |
| m417z unsafe-none | 20.30 | 22.90 | 23.40 | 5.00 |

The comparison is m417z/minhook at
`4f18d1809a81e6c700bcc4a21aeb43ade72bbf8b`, not MinHook-Detours.
Unsafe-none performs no equivalent freeze/relocation protocol. Other modes
also do not implement strict generated-code retirement. These columns are
not safety-equivalent rankings. Official/default source identity is no longer
claimed for trampoline.c: this branch intentionally hardens that shared code.

## Earlier versus current strict x64 observations

Earlier run 43374271934 used AMD EPYC 7763; the current run used AMD EPYC 9V74.
Although sample counts, compiler, OS and reported logical CPU counts match,
these are different unpaired hosts. The observations below cannot establish
regression/improvement percentages attributable to this patch. Bounded memory
queries add work during trampoline creation; quantify that isolated cost only
with a paired old/new experiment on the same host.

| Operation | Earlier median | Current median |
| --- | ---: | ---: |
| initialize | 13.10 | 12.75 |
| create_batch | 28.00 | 53.70 |
| single_enable | 2445.30 | 1808.05 |
| single_disable | 2434.65 | 1804.60 |
| queued_enable | 2465.95 | 1831.80 |
| queued_disable | 2465.95 | 1831.35 |
| freeze | 1701.20 | 1301.45 |
| unfreeze | 734.95 | 502.45 |
| uninitialize | 2890.50 | 2141.00 |

## Application integration and boundaries

[Citrine PR #363](https://github.com/raleonys/citrine-eclipse-mirage/pull/363)
imports this relocator through a separate pinned build-copy transform.
[Project run 43391349173](https://github.com/raleonys/citrine-eclipse-mirage/actions/runs/43391349173)
passed Debug 19/19 and Release 19/19 on exact head
`19a22e95931bc94c00d25ef5ec08efac976e0023`, without skips. All 19 executable
hashes and four generated source hashes were independently checked per cell.
This is focused native validation, separate from full Golden/game acceptance.
Original project vendor trees remain unchanged. PR #362 is an included pending
dependency; only the owner merges either proposal.

The fixes do not prove universal instruction, unwind, CFG/CET or concurrent
foreign-patching compatibility. Unsupported relative forms deliberately refuse
creation. Target ownership and mapping lifetime remain caller requirements;
the inherited strict completion/retirement and thread-birth limits still apply.
No release, merge, production deployment or new public repository was performed.
