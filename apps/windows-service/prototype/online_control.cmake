# Explicit include only; does not change the legacy UI/Service or launch anything.
# Requires existing orangespace_node_session + orangespace_service_windows targets,
# ORANGESPACE_RUNTIME_LIBRARY and trusted ORANGESPACE_HELPER_SHA256 / NODE_UUID.
if(NOT WIN32)
  message(FATAL_ERROR "Prototype online glue is Windows-only")
endif()
if(NOT DEFINED ORANGESPACE_PROTOTYPE_NODE_UUID OR ORANGESPACE_PROTOTYPE_NODE_UUID STREQUAL "")
  message(FATAL_ERROR "Trusted SG UUID must be injected by the private build")
endif()
if(NOT DEFINED ORANGESPACE_HELPER_SHA256 OR ORANGESPACE_HELPER_SHA256 STREQUAL "")
  message(FATAL_ERROR "Trusted Windows helper SHA256 must be injected")
endif()
set(_os_control_dir "${CMAKE_CURRENT_LIST_DIR}")
set(_os_client_dir "${_os_control_dir}/../../windows-client")
add_library(orangespace_prototype_control STATIC
  "${_os_control_dir}/online_control_win.cpp"
  "${_os_control_dir}/../src/chain_windows.cpp")
target_compile_features(orangespace_prototype_control PUBLIC cxx_std_20)
target_include_directories(orangespace_prototype_control PUBLIC "${_os_control_dir}"
  "${_os_control_dir}/../include" "${_os_client_dir}/include"
  PRIVATE "${_os_control_dir}/../../../crates/orangespace-runtime/include"
    "${_os_control_dir}/../../../crates/orangespace-https/include")
target_compile_definitions(orangespace_prototype_control PRIVATE
  ORANGESPACE_PROTOTYPE_NODE_UUID="${ORANGESPACE_PROTOTYPE_NODE_UUID}"
  ORANGESPACE_HELPER_SHA256="${ORANGESPACE_HELPER_SHA256}"
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_link_libraries(orangespace_prototype_control PUBLIC
  orangespace_node_session orangespace_service_windows "${ORANGESPACE_RUNTIME_LIBRARY}"
  advapi32 bcrypt winhttp crypt32 wtsapi32 userenv ws2_32 ntdll secur32 shell32 ole32 dbghelp iphlpapi)
# The override applies ONLY to this TU. In particular, the existing SDK's
# credential_store_win.cpp retains the management program's original identity.
add_library(orangespace_prototype_operator_client OBJECT "${_os_client_dir}/src/service_client_win.cpp")
target_include_directories(orangespace_prototype_operator_client BEFORE PRIVATE
  "${_os_client_dir}/prototype/operator-private")
target_include_directories(orangespace_prototype_operator_client PRIVATE
  "${_os_control_dir}/../include" "${_os_client_dir}/include")
target_compile_features(orangespace_prototype_operator_client PRIVATE cxx_std_20)
target_compile_definitions(orangespace_prototype_operator_client PRIVATE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
add_executable(OrangeSpacePrototypeOperator
  "${_os_client_dir}/prototype/prototype_operator_win.cpp"
  $<TARGET_OBJECTS:orangespace_prototype_operator_client>)
target_compile_features(OrangeSpacePrototypeOperator PRIVATE cxx_std_20)
target_include_directories(OrangeSpacePrototypeOperator PRIVATE "${_os_control_dir}/../include" "${_os_client_dir}/include")
target_compile_definitions(OrangeSpacePrototypeOperator PRIVATE
  ORANGESPACE_PROTOTYPE_NODE_UUID="${ORANGESPACE_PROTOTYPE_NODE_UUID}"
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_link_libraries(OrangeSpacePrototypeOperator PRIVATE orangespace_node_session advapi32 bcrypt credui user32)
if(MSVC)
  foreach(_t orangespace_prototype_control orangespace_prototype_operator_client OrangeSpacePrototypeOperator)
    set_property(TARGET ${_t} PROPERTY MSVC_RUNTIME_LIBRARY MultiThreaded)
    target_compile_options(${_t} PRIVATE /utf-8 /W4)
  endforeach()
elseif(MINGW)
  target_link_options(OrangeSpacePrototypeOperator PRIVATE -municode -static -static-libgcc -static-libstdc++)
endif()
