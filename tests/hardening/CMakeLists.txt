# SPDX-License-Identifier: BSD-2-Clause
add_executable(minhook_x64_trampoline_hardening
  trampoline_x64.c
  "${PROJECT_SOURCE_DIR}/src/trampoline.c"
  "${PROJECT_SOURCE_DIR}/src/hde/hde64.c")
set_target_properties(minhook_x64_trampoline_hardening PROPERTIES C_STANDARD 17)
target_include_directories(minhook_x64_trampoline_hardening PRIVATE
  "${PROJECT_SOURCE_DIR}/src")
add_test(NAME minhook_x64_trampoline_hardening
  COMMAND minhook_x64_trampoline_hardening)
set_tests_properties(minhook_x64_trampoline_hardening PROPERTIES TIMEOUT 30)
