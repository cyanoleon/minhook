# Fork-only native validation

The Brownfield SAFE-FREEZE contribution branch is
`safe-freeze-upstream-candidate-20261110`; its exact revision is recorded in
the repository-root `SOURCE_MANIFEST.json` as `contribution_commit`.
This separate branch adds
comparison/benchmark/stress infrastructure without changing contribution inputs.
The workflow verifies each compiled contribution input against that exact commit.
Official and m417z inputs are byte-exact, independently pinned snapshots.

The push workflow runs x86/x64 Debug/Release MSVC, exact failure controls, actual
suspended-peer fixtures, the standalone shared MinHook project, benchmarks and
stress. No upstream PR, automatic merge or release publication is performed.

To run locally on Windows from this folder:

```powershell
python -B tools/verify_inputs.py --root ../..
python -B tools/prepare_controls.py --candidate-root ../..
cmake -S . -B build/native -G "Visual Studio 17 2022" -A x64 -DSF_CANDIDATE_ROOT="$((Resolve-Path ../..).Path)"
cmake --build build/native --config Release
python -B tools/run_validation.py --build build/native/Release --output build/local-results --matrix --stress --controls --samples 200
```

See the repository-root design and license notes. The benchmark uses fixed
owned workers and never-executed hook bytes; memory/handle peaks are bounded
observations. Unsafe comparison mode is explicitly not safety-equivalent.
All failed child results are retained, never retried silently.

The stress driver treats natural thread-race refusals as explicit aborted
transactions only if original target bytes, pending queue intent and complete
peer cleanup are proved. It logs each refusal, stops/join churn, cancels the
queue, verifies rollback and retires the same engine before a new transaction.
Stable benchmark workloads still require every operation to return MH_OK.
Handle accounting starts after OS/hardware metadata collection, retains the raw
process-start count and checks zero handle growth in every completed cycle.
