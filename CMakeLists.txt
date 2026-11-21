cmake_minimum_required(VERSION 3.24)
# Static C runtime: OrangeSpace.exe runs on a machine without the Visual C++
# runtime package (the Rust library matches it, see .cargo/config.toml).
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
project(OrangeSpace VERSION 0.1.0 LANGUAGES CXX)
include(CTest)
add_subdirectory(apps/windows-client)
