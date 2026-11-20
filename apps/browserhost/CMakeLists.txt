cmake_minimum_required(VERSION 3.24)
# Two modes:
#  - included from the root build: portable protocol tests only;
#  - configured on its own with -DCEF_ROOT=<verified pinned minimal package>:
#    builds osbrowser.exe (official bootstrap) + osbrowser.dll and stages the
#    CEF runtime next to it. Windows x64 + MSVC only.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(OrangeSpaceBrowserHost LANGUAGES C CXX)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  include(CTest)
  set(_standalone ON)
else()
  set(_standalone OFF)
endif()

set(_client_include "${CMAKE_CURRENT_SOURCE_DIR}/../windows-client/include")
if(BUILD_TESTING)
  add_executable(orangespace-browserhost-protocol-tests tests/host_protocol_tests.cpp)
  target_include_directories(orangespace-browserhost-protocol-tests PRIVATE "${_client_include}")
  target_compile_features(orangespace-browserhost-protocol-tests PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_options(orangespace-browserhost-protocol-tests PRIVATE /W4 /WX /utf-8 /UNDEBUG)
  else()
    target_compile_options(orangespace-browserhost-protocol-tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
  endif()
  add_test(NAME browserhost-protocol COMMAND orangespace-browserhost-protocol-tests)
endif()

if(NOT _standalone)
  return()
endif()

if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "BrowserHost requires Windows x64 + MSVC")
endif()
if(NOT CEF_ROOT)
  message(FATAL_ERROR "Set CEF_ROOT to the extracted pinned minimal package (scripts/cef_package.py --extract-to)")
endif()
file(TO_CMAKE_PATH "${CEF_ROOT}" CEF_ROOT)
if(DEFINED USE_SANDBOX AND NOT USE_SANDBOX)
  message(FATAL_ERROR "Chromium sandbox is mandatory")
endif()
set(USE_SANDBOX ON CACHE BOOL "Chromium sandbox is mandatory" FORCE)
set(USE_INSTALLER OFF CACHE BOOL "No runtime installer" FORCE)
set(USE_ATL OFF CACHE BOOL "No sample ATL dependency" FORCE)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CEF_RUNTIME_LIBRARY_FLAG /MT CACHE STRING "Matched static CRT" FORCE)

set(_cef_dir "${CMAKE_CURRENT_SOURCE_DIR}/../windows-client/cef")
file(READ "${_cef_dir}/cef.lock.json" _pin)
foreach(_field cef_version cef_commit api_version api_hash_windows sandbox_compat)
  string(JSON PIN_${_field} GET "${_pin}" ${_field})
endforeach()
set(api_version "${PIN_api_version}")
configure_file("${_cef_dir}/cef_pin.hpp.in" "${CMAKE_CURRENT_BINARY_DIR}/generated/cef_pin.hpp" @ONLY)

find_package(Python3 3.12 REQUIRED COMPONENTS Interpreter)
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/cef_package.py"
  --root "${CEF_ROOT}" RESULT_VARIABLE _preflight)
if(NOT _preflight EQUAL 0)
  message(FATAL_ERROR "Pinned CEF package preflight failed")
endif()
list(APPEND CMAKE_MODULE_PATH "${CEF_ROOT}/cmake")
find_package(CEF REQUIRED)
add_subdirectory("${CEF_ROOT}/libcef_dll" "${CMAKE_CURRENT_BINARY_DIR}/libcef_dll_wrapper")
ADD_LOGICAL_TARGET(orangespace_libcef "${CEF_LIB_DEBUG}" "${CEF_LIB_RELEASE}")

add_library(osbrowser SHARED host_main_win.cc host_client_win.cc)
set_target_properties(osbrowser PROPERTIES OUTPUT_NAME osbrowser
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/out/$<CONFIG>")
target_include_directories(osbrowser SYSTEM PRIVATE "${CEF_ROOT}")
target_include_directories(osbrowser PRIVATE "${_cef_dir}" "${_client_include}"
  "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(osbrowser PRIVATE CEF_USE_BOOTSTRAP "CEF_API_VERSION=${PIN_api_version}"
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX WINVER=0x0A00 _WIN32_WINNT=0x0A00)
# CEF_POPULATE_VERSION_INFO uses bounded strncpy (C4996), as upstream suppresses.
target_compile_options(osbrowser PRIVATE /W4 /WX /EHsc /utf-8 /wd4996)
# libcef.dll must be delay-loaded: sandboxed children (GPU, renderer) restrict
# the DLL search path to System32, and RunWinMain loads it by absolute path.
target_link_options(osbrowser PRIVATE ${CEF_DELAYLOAD_FLAGS} /DELAYLOAD:libcef.dll)
target_link_libraries(osbrowser PRIVATE libcef_dll_wrapper orangespace_libcef ${CEF_STANDARD_LIBS} delayimp)
# Official bootstrap (contains the Chromium sandbox) renamed to load osbrowser.dll.
add_custom_command(TARGET osbrowser POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${CEF_ROOT}/Release/bootstrap.exe"
    "$<TARGET_FILE_DIR:osbrowser>/osbrowser.exe"
  COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CEF_ROOT}/Release" "$<TARGET_FILE_DIR:osbrowser>"
  COMMAND "${CMAKE_COMMAND}" -E copy_directory "${CEF_ROOT}/Resources" "$<TARGET_FILE_DIR:osbrowser>"
  COMMAND "${CMAKE_COMMAND}" -E remove -f "$<TARGET_FILE_DIR:osbrowser>/bootstrap.exe"
    "$<TARGET_FILE_DIR:osbrowser>/bootstrapc.exe" "$<TARGET_FILE_DIR:osbrowser>/libcef.lib"
  VERBATIM)
