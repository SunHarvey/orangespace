#pragma once

#ifdef _WIN32
#include <windows.h>

#include <string>
#include <vector>

namespace orangespace {
struct ProcessResult {
  unsigned long exit_code{};
  std::string output;
  std::wstring failure;
};

std::wstring widen(const std::string& input);
std::string narrow(const std::wstring& input);
std::wstring module_directory();
ProcessResult run_broker(const std::vector<std::wstring>& arguments);
}  // namespace orangespace
#endif
