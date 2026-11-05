cmake_minimum_required(VERSION 3.24)
project(OrangeSpaceClient VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(orangespace_client_model INTERFACE)
target_include_directories(orangespace_client_model INTERFACE include)

include(CTest)
# Keep the native service independently buildable, and include its portable policy
# tests in the existing root/client build without changing browser/UI behavior.
if(NOT TARGET orangespace_service_policy)
  add_subdirectory(../windows-service "${CMAKE_CURRENT_BINARY_DIR}/../windows-service")
endif()
target_link_libraries(orangespace_client_model INTERFACE orangespace_service_policy)
if(BUILD_TESTING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_test(NAME approved-ui-v2-resources
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/ui_v2_resource_tests.py")
  add_executable(orangespace-ui-v2-model-tests tests/ui_v2_model_tests.cpp)
  target_link_libraries(orangespace-ui-v2-model-tests PRIVATE orangespace_client_model)
  add_test(NAME ui-v2-model COMMAND orangespace-ui-v2-model-tests)
  if(WIN32)
    # These five contracts are compiler-independent. The sixth exercises the
    # exact caller with injected GNU/OS seams and runs on Linux alongside the
    # existing platform_ui_* caller tests; native helper policy is C++ above.
    add_test(NAME ui-v2-source-contract
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/ui_v2_tests.py"
        UiV2.test_protected_configuration_is_automatic_executable_sibling
        UiV2.test_remember_controls_persistence
        UiV2.test_tabs_and_file_context_preserve_identity
        UiV2.test_automatic_node_open_is_one_worker_and_browser_stays_locked
        UiV2.test_logout_requests_nonblocking_file_drain_before_identity_reuse)
  else()
    add_test(NAME ui-v2-source-contract
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/ui_v2_tests.py")
  endif()
  add_executable(orangespace-file-transfer-tests tests/file_transfer_tests.cpp src/file_transfer_win.cpp)
  target_link_libraries(orangespace-file-transfer-tests PRIVATE orangespace_client_model)
  if(WIN32)
    target_link_libraries(orangespace-file-transfer-tests PRIVATE orangespace_node_session bcrypt)
  endif()
  add_test(NAME file-transfer-policy COMMAND orangespace-file-transfer-tests)
  add_test(NAME file-transfer-source-contract
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/file_transfer_source_tests.py")
  if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME file-manager-production-regressions
      COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/file_manager_regression_tests.py")
  endif()
  add_executable(orangespace-file-manager-lifecycle-tests tests/file_manager_lifecycle_tests.cpp)
  target_link_libraries(orangespace-file-manager-lifecycle-tests PRIVATE orangespace_client_model)
  add_test(NAME file-manager-lifecycle COMMAND orangespace-file-manager-lifecycle-tests)
  add_test(NAME file-manager-source-contract
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/file_manager_source_tests.py")
  # These bounded policy executables use assert as their verdict. Keep those
  # assertions active in the Release configuration used by Windows CI too.
  foreach(_ui_policy_target orangespace-ui-v2-model-tests orangespace-file-transfer-tests orangespace-file-manager-lifecycle-tests)
    if(MSVC)
      target_compile_options(${_ui_policy_target} PRIVATE /UNDEBUG /utf-8)
    else()
      target_compile_options(${_ui_policy_target} PRIVATE -UNDEBUG)
    endif()
  endforeach()
  add_executable(orangespace-client-model-tests tests/model_tests.cpp)
  target_link_libraries(orangespace-client-model-tests PRIVATE orangespace_client_model)
  add_test(NAME client-model COMMAND orangespace-client-model-tests)
  add_executable(orangespace-node-session-tests tests/node_session_tests.cpp)
  target_link_libraries(orangespace-node-session-tests PRIVATE orangespace_client_model)
  add_test(NAME node-session COMMAND orangespace-node-session-tests)
  add_executable(orangespace-workspace-auth-tests tests/workspace_auth_tests.cpp)
  target_link_libraries(orangespace-workspace-auth-tests PRIVATE orangespace_client_model)
  add_test(NAME workspace-auth COMMAND orangespace-workspace-auth-tests)
  foreach(test_name node_session_lifecycle node_session_prefix node_session_error credential_store_policy)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/${test_name}_tests.cpp")
      add_executable(orangespace-${test_name}-tests "tests/${test_name}_tests.cpp")
      target_link_libraries(orangespace-${test_name}-tests PRIVATE orangespace_client_model)
      add_test(NAME ${test_name} COMMAND orangespace-${test_name}-tests)
    endif()
  endforeach()
  # Keep parser security regressions in both Linux and Windows CTest runs.
  # Allocation hooks and sanitizer instrumentation are separate evidence modes.
  option(ORANGESPACE_JSON_ALLOCATION_AUDIT "Observe parser allocations before release" ON)
  foreach(test_name zeroization transfer inplace_semantic)
    add_executable(orangespace-json-${test_name}-tests "tests/json_${test_name}_tests.cpp")
    target_link_libraries(orangespace-json-${test_name}-tests PRIVATE orangespace_client_model)
    add_test(NAME json-${test_name} COMMAND orangespace-json-${test_name}-tests)
    set_tests_properties(json-${test_name} PROPERTIES TIMEOUT 120 LABELS "json;security")
  endforeach()
  string(CONCAT _orangespace_json_flags "${CMAKE_CXX_FLAGS} "
    "${CMAKE_CXX_FLAGS_DEBUG} ${CMAKE_CXX_FLAGS_RELEASE} "
    "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} ${CMAKE_CXX_FLAGS_MINSIZEREL}")
  if(NOT ORANGESPACE_JSON_ALLOCATION_AUDIT OR _orangespace_json_flags MATCHES "sanitize")
    target_compile_definitions(orangespace-json-zeroization-tests PRIVATE ORANGESPACE_JSON_NO_ALLOC_HOOKS)
    set_tests_properties(json-zeroization PROPERTIES LABELS "json;security;semantic-only")
    message(STATUS "JSON zeroization test: semantic mode; allocation hooks disabled")
  else()
    set_tests_properties(json-zeroization PROPERTIES LABELS "json;security;allocation-audit")
  endif()
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT WIN32)
    # The positive control deliberately fails if this observer is not enabled.
    target_compile_options(orangespace-json-transfer-tests PRIVATE
      -O0 -fno-inline -fno-elide-constructors -finstrument-functions)
    target_link_options(orangespace-json-transfer-tests PRIVATE -rdynamic)
    target_link_libraries(orangespace-json-transfer-tests PRIVATE ${CMAKE_DL_LIBS})
  endif()
  add_executable(orangespace-service-client-tests tests/service_client_tests.cpp)
  target_link_libraries(orangespace-service-client-tests PRIVATE orangespace_client_model)
  add_test(NAME service-client-negative-and-policy COMMAND orangespace-service-client-tests)
  set_tests_properties(service-client-negative-and-policy PROPERTIES LABELS "policy;windows-negative-requires-absent-service")
  # Compatibility/deny policy only: this target neither links nor starts CEF.
  add_executable(orangespace-cef-policy-tests cef/tests/bootstrap_policy_tests.cpp)
  target_include_directories(orangespace-cef-policy-tests PRIVATE cef)
  add_test(NAME cef-bootstrap-policy COMMAND orangespace-cef-policy-tests)
endif()

if(WIN32)
  add_library(orangespace_service_client STATIC src/service_client_win.cpp)
  target_link_libraries(orangespace_service_client PUBLIC orangespace_client_model PRIVATE advapi32)
  target_compile_definitions(orangespace_service_client PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
  if(TARGET orangespace-service-client-tests)
    target_link_libraries(orangespace-service-client-tests PRIVATE orangespace_service_client)
  endif()
  if(MSVC)
    target_compile_options(orangespace_service_client PRIVATE /W4 /permissive- /utf-8)
  endif()
  # Service creates the shared node-session/store target before the UI targets.
  target_link_libraries(orangespace_service_client PRIVATE orangespace_node_session)
  if(BUILD_TESTING)
    foreach(test_name node_session_lifecycle node_session_prefix node_session_error credential_store_policy)
      if(TARGET orangespace-${test_name}-tests)
        target_link_libraries(orangespace-${test_name}-tests PRIVATE orangespace_node_session)
      endif()
    endforeach()
    # Explicit headless fixture; native execution is opt-in, never on startup.
    add_executable(orangespace-file-directory-native-tests WIN32
      tests/file_transfer_directory_native_win.cpp src/file_transfer_win.cpp)
    target_include_directories(orangespace-file-directory-native-tests PRIVATE include ../windows-service/include)
    target_compile_definitions(orangespace-file-directory-native-tests PRIVATE
      ORANGESPACE_FILE_LOCAL_IO_ONLY UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(orangespace-file-directory-native-tests PRIVATE bcrypt shell32 ole32 uuid advapi32)
    if(MINGW)
      target_link_options(orangespace-file-directory-native-tests PRIVATE -municode)
    endif()
    # Explicit fixture runners; never count session-0 or absent HTTPS as acceptance.
    add_executable(orangespace-credential-session-native-tests tests/credential_session_native_win.cpp)
    target_link_libraries(orangespace-credential-session-native-tests PRIVATE orangespace_node_session)
    add_executable(orangespace-credential-store-native-tests tests/credential_store_native_win.cpp src/node_session_win.cpp src/platform_session_win.cpp)
    target_link_libraries(orangespace-credential-store-native-tests PRIVATE orangespace_client_model winhttp advapi32 crypt32 shell32 ole32 bcrypt
      "${ORANGESPACE_RUNTIME_LIBRARY}" ws2_32 userenv ntdll secur32 dbghelp iphlpapi)
    target_compile_definitions(orangespace-credential-store-native-tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
    if(MINGW)
      target_link_options(orangespace-credential-session-native-tests PRIVATE -municode)
    endif()
  endif()
  # Native login/chain diagnostics share the same authenticated service client as UI.
  add_executable(OrangeSpaceLogin src/login_win.cpp)
  target_link_libraries(OrangeSpaceLogin PRIVATE orangespace_node_session orangespace_service_client)
  if(TARGET orangespace-node-session-tests)
    target_link_libraries(orangespace-node-session-tests PRIVATE orangespace_node_session)
    add_executable(orangespace-node-tls-rejection-tests tests/node_tls_rejection_win.cpp)
    target_link_libraries(orangespace-node-tls-rejection-tests PRIVATE orangespace_node_session)
    add_test(NAME node-tls-rejection COMMAND orangespace-node-tls-rejection-tests)
    set_tests_properties(node-tls-rejection PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 30)
    if(MINGW)
      target_link_options(orangespace-node-tls-rejection-tests PRIVATE -municode)
    endif()
  endif()
  if(MINGW)
    target_link_options(OrangeSpaceLogin PRIVATE -municode)
  endif()
  if(MSVC)
    target_compile_options(orangespace_node_session PRIVATE /W4 /permissive- /utf-8)
    target_compile_options(OrangeSpaceLogin PRIVATE /W4 /permissive- /utf-8)
  endif()
  enable_language(RC)
  add_executable(OrangeSpace WIN32 src/main_win.cpp src/broker_win.cpp
    src/file_manager_win.cpp src/file_transfer_win.cpp src/brand.rc)
  if(MSVC)
    # Let MSVC merge and embed the manifest once. An RC-embedded copy would
    # collide with the linker's generated RT_MANIFEST resource (CVT1100).
    target_sources(OrangeSpace PRIVATE src/app.manifest)
    if(BUILD_TESTING)
      if(CMAKE_MT)
        set(ORANGESPACE_MANIFEST_TOOL "${CMAKE_MT}")
      else()
        # Visual Studio may locate the SDK internally while CMAKE_MT is unset.
        get_filename_component(_orangespace_rc_directory "${CMAKE_RC_COMPILER}" DIRECTORY)
        find_program(ORANGESPACE_MANIFEST_TOOL NAMES mt.exe
          HINTS "${_orangespace_rc_directory}"
          PATHS "[HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows Kits/Installed Roots;KitsRoot10]/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/x64"
          REGISTRY_VIEW HOST REQUIRED)
      endif()
      add_test(NAME windows-application-manifest COMMAND ${CMAKE_COMMAND}
        "-DMT_EXECUTABLE=${ORANGESPACE_MANIFEST_TOOL}"
        "-DAPPLICATION=$<TARGET_FILE:OrangeSpace>"
        "-DOUTPUT_FILE=${CMAKE_CURRENT_BINARY_DIR}/verified-$<CONFIG>.manifest"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_manifest.cmake")
    endif()
  else()
    target_sources(OrangeSpace PRIVATE src/app.rc)
  endif()
  target_link_libraries(OrangeSpace PRIVATE orangespace_client_model orangespace_node_session orangespace_service_client
    comctl32 shell32 user32 gdi32 gdiplus comdlg32 ole32 winhttp crypt32 bcrypt)
  target_compile_definitions(OrangeSpace PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
  target_include_directories(OrangeSpace PRIVATE src)
  if(TARGET orangespace-client-model-tests)
    target_link_libraries(orangespace-client-model-tests PRIVATE shell32)
  endif()
  if(MSVC)
    target_compile_options(OrangeSpace PRIVATE /W4 /permissive- /utf-8)
    if(TARGET orangespace-client-model-tests)
      target_compile_options(orangespace-client-model-tests PRIVATE /W4 /permissive- /utf-8)
    endif()
  endif()
  if(MINGW)
    target_link_options(OrangeSpace PRIVATE -municode -Wl,--subsystem,windows)
  endif()
endif()

option(ORANGESPACE_WITH_CEF "Build the protected CEF browser host (not available yet)" OFF)
if(ORANGESPACE_WITH_CEF)
  message(FATAL_ERROR "CEF host is deliberately disabled: signed WFP/DNS enforcement and the matched CEF bootstrap/client.dll integration are not complete. See cef/README.md. Do not disable Chromium sandboxing to bypass this check.")
endif()
