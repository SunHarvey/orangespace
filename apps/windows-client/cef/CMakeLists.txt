cmake_minimum_required(VERSION 3.24)
project(OrangeSpaceCefBuildValidation LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
include(CTest)

# Linux/macOS exercise only the independent compatibility/deny policy. This
# never pretends that CEF or the Windows sandbox were built or executed.
option(ORANGESPACE_CEF_POLICY_TESTS_ONLY "Build portable policy tests, not CEF" OFF)
if(BUILD_TESTING)
  add_executable(orangespace-cef-policy-tests tests/bootstrap_policy_tests.cpp)
  target_include_directories(orangespace-cef-policy-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  if(MSVC)
    target_compile_options(orangespace-cef-policy-tests PRIVATE /W4 /WX /utf-8)
  else()
    target_compile_options(orangespace-cef-policy-tests PRIVATE -Wall -Wextra -Werror)
  endif()
  add_test(NAME cef-bootstrap-policy COMMAND orangespace-cef-policy-tests)
endif()
if(ORANGESPACE_CEF_POLICY_TESTS_ONLY)
  return()
endif()

if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "CEF build validation requires Windows x64 + MSVC; use ORANGESPACE_CEF_POLICY_TESTS_ONLY=ON for portable tests")
endif()
if(NOT CEF_ROOT)
  message(FATAL_ERROR "CEF_ROOT must be the verified pinned minimal windows64 distribution; see docs/cef-build.md")
endif()
if(DEFINED USE_SANDBOX AND NOT USE_SANDBOX)
  message(FATAL_ERROR "Chromium sandbox is mandatory")
endif()
if(DEFINED USE_INSTALLER AND USE_INSTALLER)
  message(FATAL_ERROR "Installer/network runtime resolution is not part of compile-only validation")
endif()
set(USE_SANDBOX ON CACHE BOOL "Chromium sandbox is mandatory" FORCE)
set(USE_INSTALLER OFF CACHE BOOL "No runtime installer" FORCE)
set(USE_ATL OFF CACHE BOOL "No sample ATL dependency" FORCE)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CEF_RUNTIME_LIBRARY_FLAG /MT CACHE STRING "Matched static CRT" FORCE)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/cef.lock.json" _pin)
foreach(_field cef_version cef_commit api_version api_hash_windows sandbox_compat)
  string(JSON PIN_${_field} GET "${_pin}" ${_field})
endforeach()
if(DEFINED api_version AND NOT api_version STREQUAL "${PIN_api_version}")
  message(FATAL_ERROR "CEF API version must exactly match cef.lock.json")
endif()
set(api_version "${PIN_api_version}")
configure_file(cef_pin.hpp.in "${CMAKE_CURRENT_BINARY_DIR}/generated/cef_pin.hpp" @ONLY)

# Header/layout validation at configure time; archive integrity is additionally
# enforced by scripts/cef-build-windows.ps1 before extracting to a fresh root.
find_package(Python3 3.12 REQUIRED COMPONENTS Interpreter)
execute_process(COMMAND "${Python3_EXECUTABLE}"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../scripts/cef_package.py" --root "${CEF_ROOT}"
  RESULT_VARIABLE _preflight)
if(NOT _preflight EQUAL 0)
  message(FATAL_ERROR "Pinned CEF package preflight failed")
endif()
list(APPEND CMAKE_MODULE_PATH "${CEF_ROOT}/cmake")
find_package(CEF REQUIRED)
add_subdirectory("${CEF_ROOT}/libcef_dll" "${CMAKE_CURRENT_BINARY_DIR}/libcef_dll_wrapper")
ADD_LOGICAL_TARGET(orangespace_pinned_libcef "${CEF_LIB_DEBUG}" "${CEF_LIB_RELEASE}")

# Official prebuilt bootstrap contains Chromium sandbox code. Do not link the
# obsolete cef_sandbox.lib or rebuild bootstrap from guessed WinMain glue.
add_library(orangespace_cef_client SHARED bootstrap_client_win.cc host_component.cc)
set_target_properties(orangespace_cef_client PROPERTIES OUTPUT_NAME client
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/compile-only/$<CONFIG>")
target_include_directories(orangespace_cef_client SYSTEM PRIVATE "${CEF_ROOT}")
target_include_directories(orangespace_cef_client PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../include"
  "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(orangespace_cef_client PRIVATE CEF_USE_BOOTSTRAP
  "CEF_API_VERSION=${PIN_api_version}" UNICODE _UNICODE WIN32_LEAN_AND_MEAN
  NOMINMAX WINVER=0x0A00 _WIN32_WINNT=0x0A00)
# CEF_POPULATE_VERSION_INFO uses bounded strncpy; match upstream's C4996
# suppression for that official macro while keeping other own-code warnings fatal.
target_compile_options(orangespace_cef_client PRIVATE /W4 /WX /EHsc /utf-8 /wd4996)
target_link_options(orangespace_cef_client PRIVATE ${CEF_DELAYLOAD_FLAGS})
target_link_libraries(orangespace_cef_client PRIVATE
  libcef_dll_wrapper orangespace_pinned_libcef ${CEF_STANDARD_LIBS})
add_custom_command(TARGET orangespace_cef_client POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    "${CEF_ROOT}/Release/bootstrap.exe" "$<TARGET_FILE_DIR:orangespace_cef_client>/client.exe"
  VERBATIM)
# Deliberately no runtime/resources copying, installer, LPAC ACL mutation,
# browser execution, network test, or default-client integration here.
