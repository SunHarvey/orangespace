#include "orangespace/sandbox_files.hpp"

#include "orangespace/json.hpp"
#include "orangespace/node_federation.hpp"

#include <windows.h>

#include <memory>
#include <stdexcept>

namespace orangespace::sandbox {
namespace {
using node_federation::quote;

struct CloseHandle_ {
  void operator()(HANDLE h) const noexcept {
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
  }
};
using Handle = std::unique_ptr<void, CloseHandle_>;

const json::Value& field(const json::Value& v, std::string_view key) {
  const auto* f = v.find(key);
  if (!f) throw std::runtime_error("guest reply is missing " + std::string(key));
  return *f;
}
const std::string& text(const json::Value& v, std::string_view key) {
  const auto* s = std::get_if<std::string>(&field(v, key).data);
  if (!s) throw std::runtime_error("guest reply has a bad " + std::string(key));
  return *s;
}
std::uint64_t count(const json::Value& v, std::string_view key) {
  const auto* d = std::get_if<double>(&field(v, key).data);
  if (!d || *d < 0 || *d > 1099511627776.0 || *d != static_cast<double>(static_cast<std::uint64_t>(*d)))
    throw std::runtime_error("guest reply has a bad " + std::string(key));
  return static_cast<std::uint64_t>(*d);
}

class Cancelled : public std::runtime_error {
 public:
  Cancelled() : std::runtime_error("cancelled") {}
};
}  // namespace

std::string GuestFiles::call(const std::string& request, unsigned long timeout_ms) {
  auto reply = agent_.request(request, timeout_ms);
  const auto value = json::parse(reply);
  if (const auto* e = value.find("error")) {
    const auto* s = std::get_if<std::string>(&e->data);
    throw std::runtime_error("guest: " + (s ? s->substr(0, 240) : std::string("refused")));
  }
  return reply;
}

void GuestFiles::cancel_transfer(const std::string& transfer) noexcept {
  try {
    agent_.request("{\"op\":\"files.cancel\",\"transfer\":" + quote(transfer) + "}", 10000);
  } catch (...) {
  }
}

std::vector<GuestFile> GuestFiles::list(const std::string& sandbox) {
  const auto reply = json::parse(call("{\"op\":\"files.list\",\"user\":" + quote(user_id_) +
                                      ",\"sandbox\":" + quote(sandbox) + "}"));
  const auto* files = std::get_if<json::Value::Array>(&field(reply, "files").data);
  if (!files) throw std::runtime_error("guest reply has a bad file list");
  std::vector<GuestFile> out;
  for (const auto& f : *files) {
    const auto* modified = std::get_if<double>(&field(f, "modified_ns").data);
    out.push_back({text(f, "name"), count(f, "size"), modified ? static_cast<std::int64_t>(*modified / 1e9) : 0});
  }
  return out;
}

std::string GuestFiles::push(const std::string& sandbox, const std::filesystem::path& local, std::string_view name,
                             const std::atomic<bool>& cancel, const Progress& progress) {
  Handle file(CreateFileW(local.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
  if (file.get() == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot read the local copy");
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(file.get(), &size) || size.QuadPart < 0) throw std::runtime_error("cannot read the local copy");
  const auto total = static_cast<std::uint64_t>(size.QuadPart);
  const auto started = json::parse(call("{\"op\":\"files.push\",\"user\":" + quote(user_id_) + ",\"sandbox\":" +
                                        quote(sandbox) + ",\"name\":" + quote(name) +
                                        ",\"size\":" + std::to_string(total) + "}"));
  const auto transfer = text(started, "transfer");
  try {
    std::string chunk(kChunk, '\0');
    std::uint64_t done = 0;
    while (done < total) {
      if (cancel.load()) throw Cancelled();
      DWORD got = 0;
      const auto want = static_cast<DWORD>(std::min<std::uint64_t>(kChunk, total - done));
      if (!ReadFile(file.get(), chunk.data(), want, &got, nullptr) || got != want)
        throw std::runtime_error("the local copy changed while it was sent");
      call("{\"op\":\"files.write\",\"transfer\":" + quote(transfer) + ",\"data\":\"" +
           base64::encode(std::string_view(chunk.data(), got)) + "\"}");
      done += got;
      if (progress) progress(done, total);
    }
    const auto finished = json::parse(call("{\"op\":\"files.finish\",\"transfer\":" + quote(transfer) + "}", 180000));
    return text(finished, "name");
  } catch (...) {
    cancel_transfer(transfer);
    throw;
  }
}

void GuestFiles::pull(const std::string& sandbox, std::string_view name, const std::filesystem::path& local,
                      const std::atomic<bool>& cancel, const Progress& progress) {
  Handle file(CreateFileW(local.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
  if (file.get() == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot create the local copy");
  bool kept = false;
  struct Discard {
    HANDLE h;
    const bool& kept;
    ~Discard() {
      if (kept) return;
      FILE_DISPOSITION_INFO gone{TRUE};
      SetFileInformationByHandle(h, FileDispositionInfo, &gone, sizeof gone);
    }
  } discard{file.get(), kept};
  const auto started = json::parse(call("{\"op\":\"files.pull\",\"user\":" + quote(user_id_) + ",\"sandbox\":" +
                                        quote(sandbox) + ",\"name\":" + quote(name) + "}"));
  const auto transfer = text(started, "transfer");
  const auto total = count(started, "size");
  try {
    std::uint64_t done = 0;
    std::string bytes;
    for (bool end = false; !end;) {
      if (cancel.load()) throw Cancelled();
      const auto reply = json::parse(call("{\"op\":\"files.read\",\"transfer\":" + quote(transfer) + "}"));
      if (!base64::decode(text(reply, "data"), bytes) || bytes.size() > kChunk || bytes.size() > total - done)
        throw std::runtime_error("guest sent a bad chunk");
      const auto* e = std::get_if<bool>(&field(reply, "end").data);
      if (!e) throw std::runtime_error("guest reply has a bad end");
      end = *e;
      DWORD wrote = 0;
      if (!bytes.empty() && (!WriteFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &wrote, nullptr) ||
                             wrote != bytes.size()))
        throw std::runtime_error("cannot write the local copy");
      done += bytes.size();
      if (progress) progress(done, total);
      if (!end && bytes.empty()) throw std::runtime_error("guest sent an empty chunk");
    }
    if (done != total) throw std::runtime_error("the sandbox file changed while it was read");
  } catch (...) {
    cancel_transfer(transfer);
    throw;
  }
  if (!FlushFileBuffers(file.get())) throw std::runtime_error("cannot write the local copy");
  kept = true;
}

}  // namespace orangespace::sandbox
