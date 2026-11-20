if(NOT WIN32)
  return()
endif()
add_executable(orangespace-devlaunch WIN32 devlaunch_win.cpp)
target_include_directories(orangespace-devlaunch PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../apps/windows-client/include")
target_link_libraries(orangespace-devlaunch PRIVATE orangespace_sandbox ws2_32 bcrypt comctl32 shell32 ole32)
if(MSVC)
  target_compile_options(orangespace-devlaunch PRIVATE /W4 /utf-8)
  # Start elevated (it plays the Service: WFP); no requireAdministrator
  # manifest because the same binary is relaunched non-elevated as the UI and
  # as the BrowserHost spawn stub.
endif()
add_executable(orangespace-netcheck netcheck_win.cpp)
target_link_libraries(orangespace-netcheck PRIVATE orangespace_sandbox ws2_32)
if(MSVC)
  target_compile_options(orangespace-netcheck PRIVATE /W4 /utf-8)
endif()
