# Include from the separately configured SG prototype build, after the existing
# orangespace_node_session target. Never add operator-private to the SDK/UI.
if(NOT WIN32 OR NOT TARGET orangespace_node_session)
  message(FATAL_ERROR "SG GUI requires Windows and the existing node/session SDK")
endif()
if(NOT ORANGESPACE_PROTOTYPE_NODE_UUID)
  message(FATAL_ERROR "Supply the selected trusted SG UUID as a build input")
endif()
set(_sg_client "${CMAKE_CURRENT_LIST_DIR}/..")
# Preserve the SDK/Broker/DPAPI namespace; only the pipe client TU receives the
# private service-name header, not this public installation identity.
target_compile_definitions(orangespace_node_session PUBLIC
  ORANGESPACE_DEVELOPMENT_INSTALL_ID="sg-v25-20261104")
add_library(orangespace_sg_gui_service_client STATIC "${_sg_client}/src/service_client_win.cpp")
target_include_directories(orangespace_sg_gui_service_client BEFORE PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/operator-private")
target_include_directories(orangespace_sg_gui_service_client PUBLIC
  "${_sg_client}/include" "${_sg_client}/../windows-service/include")
target_compile_definitions(orangespace_sg_gui_service_client PRIVATE
  UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_link_libraries(orangespace_sg_gui_service_client PUBLIC orangespace_node_session advapi32)
enable_language(RC)
add_executable(OrangeSpace WIN32 "${_sg_client}/src/main_win.cpp"
  "${_sg_client}/src/broker_win.cpp" "${_sg_client}/src/file_manager_win.cpp"
  "${_sg_client}/src/file_transfer_win.cpp" "${_sg_client}/src/brand.rc")
if(MSVC)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND
      CMAKE_LINKER MATCHES "(^|[/\\\\])lld-link(\\.exe)?$")
    # LLD 19's manifest merge corrupts asm.v3 UAC namespaces. Embed the exact
    # source as RT_MANIFEST 1; disable only the linker's automatic merge.
    target_sources(OrangeSpace PRIVATE "${_sg_client}/src/app.rc")
    target_link_options(OrangeSpace PRIVATE /MANIFEST:NO)
  else()
    target_sources(OrangeSpace PRIVATE "${_sg_client}/src/app.manifest")
  endif()
  target_compile_options(OrangeSpace PRIVATE /W4 /utf-8)
  target_compile_options(orangespace_sg_gui_service_client PRIVATE /W4 /utf-8)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    # Existing local-IO SDK enum forward declaration; MSVC accepts its NT class.
    target_compile_options(OrangeSpace PRIVATE /clang:-Wno-enum-constexpr-conversion)
  endif()
else()
  target_sources(OrangeSpace PRIVATE "${_sg_client}/src/app.rc")
  target_link_options(OrangeSpace PRIVATE -municode)
endif()
target_include_directories(OrangeSpace PRIVATE "${_sg_client}/include" "${_sg_client}/src" "${_sg_client}/../windows-service/include")
target_compile_definitions(OrangeSpace PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
  ORANGESPACE_PROTOTYPE_NODE_UUID="${ORANGESPACE_PROTOTYPE_NODE_UUID}")
target_link_libraries(OrangeSpace PRIVATE orangespace_sg_gui_service_client orangespace_node_session
  comctl32 shell32 user32 gdi32 gdiplus comdlg32 ole32 uuid winhttp crypt32 bcrypt advapi32 userenv)
