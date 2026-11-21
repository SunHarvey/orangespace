#pragma once
// The 文件 window of one sandbox (Windows only): the user's personal files on
// the sandbox's bound node beside the sandbox's Downloads folder, with copies
// either way. A copy passes through a private staging folder of this Windows
// user (deleted when the copy ends); the sandbox side goes through the guest
// agent as the sandbox's own UID. Nothing is ever replaced: the sandbox side
// picks a free name, and the node side refuses a name that already exists.
#include "orangespace/file_transfer.hpp"
#include "orangespace/sandbox_files.hpp"

#include <windows.h>

#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <string>

namespace orangespace::sandbox {

struct FilesTarget {
  std::string sandbox_id, sandbox_name, node_name;
  files::FileContext context;    // bound node, Centre envelope, trust files
  std::filesystem::path staging;  // private folder for copies in transit
};

class FilesWindow;

// All calls on the UI thread.
class FilesWindows {
 public:
  FilesWindows(HWND owner, GuestFiles& guest, std::function<void(const std::string&)> log);
  ~FilesWindows();
  FilesWindows(const FilesWindows&) = delete;
  FilesWindows& operator=(const FilesWindows&) = delete;

  // Opens the window of this sandbox, or brings it to the front.
  void open(const FilesTarget& target);
  // Cancels any copy in progress, waits for it to stop, closes the window.
  void close(const std::string& sandbox_id);
  void close_all();

 private:
  friend class FilesWindow;
  HWND owner_;
  GuestFiles& guest_;
  std::function<void(const std::string&)> log_;
  std::map<std::string, std::unique_ptr<FilesWindow>> windows_;
};

}  // namespace orangespace::sandbox
