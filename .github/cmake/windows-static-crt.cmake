# Configure CMake dependencies to use the static MSVC CRT. This file is loaded
# before each dependency's project() call through CMAKE_TOOLCHAIN_FILE.
set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
cmake_policy(SET CMP0091 NEW)
set(
  CMAKE_MSVC_RUNTIME_LIBRARY
  "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  CACHE STRING "MSVC runtime linkage"
  FORCE
)
