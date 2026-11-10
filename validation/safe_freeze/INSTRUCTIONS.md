# Fork-only native validation

The contribution branch is `safe-freeze-upstream-candidate-20261110` at
`063c281cf31f2a259cb65c274d150614bbbf67a7`. This separate branch adds
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
