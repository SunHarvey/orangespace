#include "orangespace/credential_store.hpp"
#include "orangespace/platform_credential_store.hpp"
#ifdef _WIN32
#include "../../windows-service/include/orangespace/install_identity.hpp"
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <dpapi.h>
#include <bcrypt.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>

namespace orangespace::node_session {
namespace {
[[noreturn]] void fail() { throw std::runtime_error("user credential store operation failed"); }
void checked(bool result) { if (!result) fail(); }
struct Close { void operator()(void* p) const noexcept { if (p && p != INVALID_HANDLE_VALUE) CloseHandle(p); } };
struct Free { void operator()(void* p) const noexcept { if (p) LocalFree(p); } };
using Handle = std::unique_ptr<void, Close>;
using Local = std::unique_ptr<void, Free>;
struct Secret {
  std::string bytes;
  ~Secret() { detail::wipe(bytes.data(), bytes.size()); }
};
struct Blob {
  DATA_BLOB value{};
  Blob() = default;
  Blob(const Blob&) = delete;
  Blob& operator=(const Blob&) = delete;
  Blob(Blob&& other) noexcept : value(other.value) { other.value = {}; }
  Blob& operator=(Blob&&) = delete;
  ~Blob() { if (value.pbData) { detail::wipe(value.pbData, value.cbData); LocalFree(value.pbData); } }
};
std::int64_t now() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
struct User {
  Handle token;
  std::vector<unsigned char> information;
  std::wstring sid_text;
  PSID sid{};
  User() {
    HANDLE thread = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &thread)) { Handle close(thread); fail(); }
    checked(GetLastError() == ERROR_NO_TOKEN);
    HANDLE raw = nullptr;
    checked(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw) != FALSE);
    token.reset(raw);
    DWORD session = 0, size = sizeof(session);
    checked(GetTokenInformation(token.get(), TokenSessionId, &session, size, &size) != FALSE && session != 0);
    size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    checked(GetLastError() == ERROR_INSUFFICIENT_BUFFER && size <= 65536);
    information.resize(size);
    checked(GetTokenInformation(token.get(), TokenUser, information.data(), size, &size) != FALSE);
    sid = reinterpret_cast<TOKEN_USER*>(information.data())->User.Sid;
    checked(IsValidSid(sid) && !IsWellKnownSid(sid, WinLocalSystemSid) &&
            !IsWellKnownSid(sid, WinLocalServiceSid) && !IsWellKnownSid(sid, WinNetworkServiceSid));
    wchar_t* text = nullptr;
    checked(ConvertSidToStringSidW(sid, &text) != FALSE);
    Local storage(text); sid_text = text;
  }
  bool own(PSID other) const {
    return other && IsValidSid(other) && (EqualSid(sid, other) || IsWellKnownSid(other, WinLocalSystemSid));
  }
  bool ancestor_owner(PSID other) const {
    if (own(other) || (other && IsWellKnownSid(other, WinBuiltinAdministratorsSid))) return true;
    PSID ti = nullptr;
    checked(ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti) != FALSE);
    Local storage(ti);
    return other && IsValidSid(other) && EqualSid(ti, other);
  }
};
void verify_acl(HANDLE handle, const User& user, bool ancestor) {
  PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR raw = nullptr;
  checked(GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
      &owner, nullptr, &acl, nullptr, &raw) == ERROR_SUCCESS);
  Local storage(raw);
  SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
  checked(GetSecurityDescriptorControl(raw, &control, &revision) != FALSE);
  std::vector<detail::Ace> entries;
  if (acl) {
    checked(IsValidAcl(acl) != FALSE);
    for (DWORD index = 0; index < acl->AceCount; ++index) {
      void* raw_ace = nullptr; checked(GetAce(acl, index, &raw_ace) != FALSE);
      const auto* header = static_cast<ACE_HEADER*>(raw_ace);
      if (header->AceFlags & INHERIT_ONLY_ACE) continue;
      if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
        const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        const auto sid = const_cast<DWORD*>(&ace->SidStart);
        entries.push_back({detail::AceKind::allow, ancestor ? user.ancestor_owner(sid) : user.own(sid), ace->Mask});
      } else if (header->AceType == ACCESS_DENIED_ACE_TYPE) entries.push_back({detail::AceKind::deny, false, 0});
      else entries.push_back({detail::AceKind::unsupported, false, 0});
    }
  }
  const bool present = acl && (control & SE_DACL_PRESENT);
  const bool protected_dacl = (control & SE_DACL_PROTECTED) != 0;
  checked(ancestor ? detail::secure_acl(user.ancestor_owner(owner), protected_dacl, present, entries, true)
                   : credential_detail::secure_user_acl(user.own(owner), protected_dacl, present, entries));
}
void verify_object(HANDLE handle, bool directory) {
  FILE_ATTRIBUTE_TAG_INFO attributes{};
  checked(GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &attributes, sizeof(attributes)) != FALSE);
  checked(!(attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT));
  checked(((attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory);
  if (!directory) {
    BY_HANDLE_FILE_INFORMATION info{};
    checked(GetFileInformationByHandle(handle, &info) != FALSE && info.nNumberOfLinks == 1);
  }
}
// Open a single leaf relative to the already validated directory object. The
// native API avoids resolving even a reparse-modified product pathname again.
Handle relative_file(HANDLE directory, const std::wstring& leaf, DWORD access, DWORD sharing,
                     bool create, PSECURITY_DESCRIPTOR descriptor = nullptr) {
  checked(!leaf.empty() && leaf.size() <= 128 && leaf.find_first_of(L"\\\\/:") == std::wstring::npos);
  using Create = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
      PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
  const auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
  checked(address != nullptr);
  Create create_file = nullptr;
  static_assert(sizeof(create_file) == sizeof(address));
  std::memcpy(&create_file, &address, sizeof(create_file));
  UNICODE_STRING name{};
  name.Length = static_cast<USHORT>(leaf.size() * sizeof(wchar_t));
  name.MaximumLength = name.Length;
  name.Buffer = const_cast<wchar_t*>(leaf.data());
  OBJECT_ATTRIBUTES object{};
  object.Length = sizeof(object); object.RootDirectory = directory; object.ObjectName = &name;
  object.Attributes = 0x40u | 0x1000u; // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
  object.SecurityDescriptor = descriptor;
  IO_STATUS_BLOCK information{};
  HANDLE raw = nullptr;
  // FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
  // FILE_OPEN_REPARSE_POINT; creation additionally uses FILE_WRITE_THROUGH.
  const ULONG options = 0x40u | 0x20u | 0x200000u | (create ? 0x2u : 0u);
  const auto status = create_file(&raw, access | SYNCHRONIZE, &object, &information, nullptr,
      FILE_ATTRIBUTE_NORMAL, sharing, create ? 2u : 1u, options, nullptr, 0); // FILE_CREATE / FILE_OPEN
  Handle result(raw);
  if (!create && static_cast<ULONG>(status) == 0xc0000034u) return {}; // STATUS_OBJECT_NAME_NOT_FOUND
  checked(status >= 0 && result != nullptr);
  return result;
}
enum class StoreKind { node, platform };
std::wstring credential_directory_leaf(StoreKind kind) {
  std::wstring leaf = kind == StoreKind::node ? L"OrangeSpace-Credentials-v1"
      : std::wstring(platform_session::credential_detail::directory_name);
  if (!install_identity::suffix.empty()) {
    leaf += L".Dev.";
    leaf.append(install_identity::suffix.begin(), install_identity::suffix.end());
  }
  return leaf;
}
struct Directory {
  struct Com {
    HRESULT result{CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)};
    Com() { checked(SUCCEEDED(result) || result == RPC_E_CHANGED_MODE); }
    ~Com() { if (SUCCEEDED(result)) CoUninitialize(); }
  } com;
  User user;
  std::wstring path;
  Local descriptor;
  SECURITY_ATTRIBUTES attributes{};
  std::vector<Handle> ancestors;
  StoreKind kind;
  explicit Directory(StoreKind selected = StoreKind::node) : kind(selected) {
    const auto sddl = L"O:" + user.sid_text + L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.sid_text + L")";
    PSECURITY_DESCRIPTOR raw = nullptr;
    checked(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &raw, nullptr) != FALSE);
    descriptor.reset(raw);
    attributes = {sizeof(SECURITY_ATTRIBUTES), raw, FALSE};
    PWSTR folder = nullptr;
    const auto result = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &folder);
    struct FreeFolder { PWSTR p; ~FreeFolder() { CoTaskMemFree(p); } } storage{folder};
    checked(SUCCEEDED(result) && folder);
    const std::wstring local(folder);
    checked(detail::explicit_local_path(local));
    const auto root = local.substr(0, 3);
    checked(GetDriveTypeW(root.c_str()) == DRIVE_FIXED);
    DWORD flags = 0;
    checked(GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, &flags, nullptr, 0) != FALSE && (flags & FS_PERSISTENT_ACLS));
    std::vector<std::wstring> parts{root};
    for (auto pos = local.find(L'\\', 3); pos != std::wstring::npos; pos = local.find(L'\\', pos + 1)) parts.push_back(local.substr(0, pos));
    parts.push_back(local);
    for (const auto& part : parts) {
      Handle handle(CreateFileW(part.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
          OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
      checked(handle.get() != INVALID_HANDLE_VALUE);
      verify_object(handle.get(), true); verify_acl(handle.get(), user, true);
      ancestors.push_back(std::move(handle));
    }
    // Separate protected product root: do not alter broker/profile directories.
    path = local + L"\\" + credential_directory_leaf(kind);
    checked(detail::explicit_local_path(path));
    if (!CreateDirectoryW(path.c_str(), &attributes)) checked(GetLastError() == ERROR_ALREADY_EXISTS);
    Handle handle(CreateFileW(path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    checked(handle.get() != INVALID_HANDLE_VALUE);
    verify_object(handle.get(), true); verify_acl(handle.get(), user, false);
    ancestors.push_back(std::move(handle));
  }
  void verify() const {
    for (std::size_t i = 0; i < ancestors.size(); ++i) {
      verify_object(ancestors[i].get(), true);
      verify_acl(ancestors[i].get(), user, i + 1 < ancestors.size());
    }
  }
  std::wstring filename(const detail::NodeEntry& node) const {
    checked(kind == StoreKind::node ? detail::uuid(node.node_id)
        : platform_session::credential_detail::storage_id(node.node_id));
    return (kind == StoreKind::node ? L"" : L"central-") +
        std::wstring(node.node_id.begin(), node.node_id.end()) + L".dpapi";
  }
  Handle open(const detail::NodeEntry& node) const {
    return relative_file(ancestors.back().get(), filename(node),
        READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA | DELETE, FILE_SHARE_READ, false);
  }
  std::string scope(const detail::NodeEntry& node) const {
    if (kind == StoreKind::platform)
      return platform_session::credential_detail::entropy(std::string(user.sid_text.begin(), user.sid_text.end()), node.name);
    return credential_detail::entropy(std::string(user.sid_text.begin(), user.sid_text.end()), node);
  }
};
void purge(HANDLE file) {
  FILE_DISPOSITION_INFO info{TRUE};
  checked(SetFileInformationByHandle(file, FileDispositionInfo, &info, sizeof(info)) != FALSE);
}
Blob encrypt(std::string_view plaintext, std::string_view entropy) {
  checked(!plaintext.empty() && plaintext.size() <= 16384);
  DATA_BLOB input{static_cast<DWORD>(plaintext.size()), reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data()))};
  DATA_BLOB extra{static_cast<DWORD>(entropy.size()), reinterpret_cast<BYTE*>(const_cast<char*>(entropy.data()))};
  Blob output;
  checked(CryptProtectData(&input, L"OrangeSpace user API session v1", &extra, nullptr, nullptr,
      CRYPTPROTECT_UI_FORBIDDEN, &output.value) != FALSE);
  checked(output.value.cbData && output.value.cbData <= 65536);
  return output;
}
Blob decrypt(std::string& encrypted, std::string_view entropy) {
  DATA_BLOB input{static_cast<DWORD>(encrypted.size()), reinterpret_cast<BYTE*>(encrypted.data())};
  DATA_BLOB extra{static_cast<DWORD>(entropy.size()), reinterpret_cast<BYTE*>(const_cast<char*>(entropy.data()))};
  Blob output;
  checked(CryptUnprotectData(&input, nullptr, &extra, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output.value) != FALSE);
  checked(output.value.cbData && output.value.cbData <= 16384);
  return output;
}
void atomic_write_leaf(Directory& directory, const std::wstring& target, const Blob& encrypted,
                       bool preserve_promoted = false) {
  unsigned char random[16]{};
  checked(BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0);
  constexpr wchar_t hex[] = L"0123456789abcdef";
  std::wstring leaf = L"stage-";
  for (auto c : random) { leaf += hex[c >> 4]; leaf += hex[c & 15]; }
  leaf += L".tmp";
  Handle file = relative_file(directory.ancestors.back().get(), leaf,
      GENERIC_READ | GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES | DELETE, 0, true,
      directory.attributes.lpSecurityDescriptor);
  bool promoted = false;
  try {
    verify_object(file.get(), false); verify_acl(file.get(), directory.user, false);
    DWORD written = 0;
    checked(WriteFile(file.get(), encrypted.value.pbData, encrypted.value.cbData, &written, nullptr) != FALSE && written == encrypted.value.cbData);
    checked(FlushFileBuffers(file.get()) != FALSE);
    directory.verify(); verify_acl(file.get(), directory.user, false);
    std::vector<unsigned char> buffer(sizeof(FILE_RENAME_INFO) + target.size() * sizeof(wchar_t));
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    rename->ReplaceIfExists = TRUE;
    rename->RootDirectory = directory.ancestors.back().get();
    rename->FileNameLength = static_cast<DWORD>(target.size() * sizeof(wchar_t));
    std::memcpy(rename->FileName, target.data(), rename->FileNameLength);
    // Win32's wrapper can reject a non-null RootDirectory; use the native
    // FileRenameInformation operation so the target resolves from the held
    // directory object, not by reopening its pathname. ntdll is already loaded.
    using Rename = NTSTATUS (NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
    const auto address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile");
    checked(address != nullptr);
    Rename rename_file = nullptr;
    static_assert(sizeof(rename_file) == sizeof(address));
    std::memcpy(&rename_file, &address, sizeof(rename_file));
    IO_STATUS_BLOCK status{};
    checked(rename_file(file.get(), &status, rename, static_cast<ULONG>(buffer.size()),
        static_cast<FILE_INFORMATION_CLASS>(10)) >= 0); // FileRenameInformation
    promoted = true;
    checked(FlushFileBuffers(file.get()) != FALSE);
    LARGE_INTEGER zero{};
    checked(SetFilePointerEx(file.get(), zero, nullptr, FILE_BEGIN) != FALSE);
    Secret readback{std::string(encrypted.value.cbData, '\0')};
    DWORD count = 0;
    checked(ReadFile(file.get(), readback.bytes.data(), encrypted.value.cbData, &count, nullptr) != FALSE &&
        count == encrypted.value.cbData && !std::memcmp(readback.bytes.data(), encrypted.value.pbData, count));
    directory.verify(); verify_object(file.get(), false); verify_acl(file.get(), directory.user, false);
  } catch (...) {
    // Preserve promoted logout intent on uncertain durability. A credential
    // save that failed readback/verification must not leave a restorable blob.
    if (!promoted || !preserve_promoted) purge(file.get());
    throw;
  }
}
void atomic_write(Directory& directory, const detail::NodeEntry& node, const Blob& encrypted) {
  atomic_write_leaf(directory, directory.filename(node), encrypted);
}
std::wstring pending_leaf(Directory& directory, const detail::NodeEntry& node) {
  return directory.filename(node) + L".logout";
}
// Private, persistent, empty lock leaf; the OS releases ownership on process
// death. No name-based mutex, caller identity, or alternate state directory.
struct NodeLock {
  Handle file;
  NodeLock(Directory& directory, const detail::NodeEntry& node, bool wait = true) {
    const auto leaf = directory.filename(node) + L".lock";
    const auto deadline = GetTickCount64() + 2000;
    do {
      try {
        file = relative_file(directory.ancestors.back().get(), leaf,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, false);
        if (!file) file = relative_file(directory.ancestors.back().get(), leaf,
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL, 0, true, directory.attributes.lpSecurityDescriptor);
      } catch (...) {
        if (!wait || GetTickCount64() >= deadline) throw;
        Sleep(10); continue;
      }
      verify_object(file.get(), false); verify_acl(file.get(), directory.user, false);
      LARGE_INTEGER size{};
      checked(GetFileSizeEx(file.get(), &size) != FALSE && size.QuadPart == 0);
      directory.verify();
      return;
    } while (GetTickCount64() < deadline);
    fail();
  }
};
Handle open_pending(Directory& directory, const detail::NodeEntry& node) {
  auto file = relative_file(directory.ancestors.back().get(), pending_leaf(directory, node),
      GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES | DELETE, FILE_SHARE_READ, false);
  if (file) {verify_object(file.get(), false); verify_acl(file.get(), directory.user, false);}
  directory.verify();
  return file;
}
bool pending(Directory& directory, const detail::NodeEntry& node) {
  // Presence alone denies restoration. Malformed bytes are never reset, and no
  // DPAPI or HTTP operation is needed to enforce the gate.
  return open_pending(directory, node) != nullptr;
}
void require_not_pending(Directory& directory, const detail::NodeEntry& node) {
  credential_detail::require_no_pending(pending(directory, node));
}
constexpr std::string_view logout_intent = "OrangeSpace/nonsecret/pending-logout/v1";
std::string logout_scope(Directory& directory, const detail::NodeEntry& node) {
  return directory.scope(node) + std::string("\0pending-logout/v1", 18);
}
void verify_pending(Directory& directory, const detail::NodeEntry& node, HANDLE file) {
  LARGE_INTEGER size{};
  checked(GetFileSizeEx(file, &size) != FALSE && size.QuadPart > 0 && size.QuadPart <= 65536);
  Secret bytes{std::string(static_cast<std::size_t>(size.QuadPart), '\0')};
  DWORD count = 0;
  checked(ReadFile(file, bytes.bytes.data(), static_cast<DWORD>(bytes.bytes.size()), &count, nullptr) != FALSE &&
      count == bytes.bytes.size());
  const auto plain = decrypt(bytes.bytes, logout_scope(directory, node));
  checked(std::string_view(reinterpret_cast<char*>(plain.value.pbData), plain.value.cbData) == logout_intent);
  directory.verify(); verify_acl(file, directory.user, false);
}
void commit_pending(Directory& directory, const detail::NodeEntry& node) {
  auto file = open_pending(directory, node);
  if (file) {verify_pending(directory, node, file.get()); return;}
  const auto blob = encrypt(logout_intent, logout_scope(directory, node));
  atomic_write_leaf(directory, pending_leaf(directory, node), blob, true);
  file = open_pending(directory, node);
  checked(file != nullptr);
  verify_pending(directory, node, file.get());
  // Commit point: protected write-through atomic promotion, flush, ciphertext
  // readback and bound DPAPI verification completed. No deletion precedes this.
}
void erase_pending(Directory& directory, const detail::NodeEntry& node) {
  struct Transaction {
    Directory& directory; const detail::NodeEntry& node;
    void commit() {commit_pending(directory, node);}
    void remove_blob() {
      auto file = directory.open(node);
      if (file) {directory.verify(); purge(file.get());}
    }
    void verify_absent() {checked(!directory.open(node)); directory.verify();}
    void clear() {
      auto file = open_pending(directory, node);
      checked(file != nullptr); verify_pending(directory, node, file.get());
      // Exact original node filename was reopened under held ancestors and lock.
      verify_absent(); purge(file.get()); file.reset();
      checked(!open_pending(directory, node));
    }
  } transaction{directory, node};
  credential_detail::pending_erase(transaction);
}
} // namespace

void CredentialStore::save(const TrustedCatalog& catalog, std::string_view alias, const NodeSession& session) {
  const auto found = std::find_if(catalog.nodes_.begin(), catalog.nodes_.end(), [&](const auto& n) { return n.name == alias; });
  checked(found != catalog.nodes_.end());
  Directory directory;
  // Access never queues behind logout and then misses an already-cleared
  // marker. A concurrent holder fails this attempt; callers must start anew.
  NodeLock lock(directory, *found, false);
  require_not_pending(directory, *found);
  Secret envelope{session.credential_envelope()};
  (void)detail::validate_envelope(*found, envelope.bytes, now());
  const auto blob = encrypt(envelope.bytes, directory.scope(*found));
  atomic_write(directory, *found, blob);
}
NodeSession CredentialStore::load(const TrustedCatalog& catalog, std::string_view alias) {
  const auto found = std::find_if(catalog.nodes_.begin(), catalog.nodes_.end(), [&](const auto& n) { return n.name == alias; });
  checked(found != catalog.nodes_.end());
  Directory directory;
  // Access never queues behind logout and then misses an already-cleared
  // marker. A concurrent holder fails this attempt; callers must start anew.
  NodeLock lock(directory, *found, false);
  require_not_pending(directory, *found);
  auto file = directory.open(*found);
  checked(file != nullptr);
  try {
    verify_object(file.get(), false); verify_acl(file.get(), directory.user, false);
    LARGE_INTEGER size{};
    checked(GetFileSizeEx(file.get(), &size) != FALSE && size.QuadPart > 0 && size.QuadPart <= 65536);
    Secret encrypted{std::string(static_cast<std::size_t>(size.QuadPart), '\0')};
    DWORD count = 0;
    checked(ReadFile(file.get(), encrypted.bytes.data(), static_cast<DWORD>(encrypted.bytes.size()), &count, nullptr) != FALSE && count == encrypted.bytes.size());
    directory.verify(); verify_acl(file.get(), directory.user, false);
    const auto plaintext = decrypt(encrypted.bytes, directory.scope(*found));
    const std::string_view envelope(reinterpret_cast<const char*>(plaintext.value.pbData), plaintext.value.cbData);
    return NodeSession::restore_envelope(catalog, alias, envelope);
  } catch (...) {
    file.reset();
    // Expiry/invalid credential cleanup uses the same write-ahead transaction.
    // Preserve the original failure; never silently reset an unknown marker.
    try {erase_pending(directory, *found);} catch (...) {}
    throw;
  }
}
void CredentialStore::erase(const TrustedCatalog& catalog, std::string_view alias) {
  const auto found = std::find_if(catalog.nodes_.begin(), catalog.nodes_.end(), [&](const auto& n) { return n.name == alias; });
  checked(found != catalog.nodes_.end());
  Directory directory;
  NodeLock lock(directory, *found);
  erase_pending(directory, *found);
}
} // namespace orangespace::node_session

namespace orangespace::platform_session {
// Shared private primitives retain the original held-ancestor, relative-file,
// ACL, write-through atomic replacement and pending-logout transaction policy.
using namespace node_session;
namespace {
node_session::detail::NodeEntry storage_key(const PlatformConfig& config) {
  const auto bootstrap = credential_detail::validate_origin(config.api_origin());
  struct Algorithm {
    BCRYPT_ALG_HANDLE handle{};
    ~Algorithm() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
  } algorithm;
  checked(BCryptOpenAlgorithmProvider(&algorithm.handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0);
  unsigned char digest[32]{};
  checked(BCryptHash(algorithm.handle, nullptr, 0,
      reinterpret_cast<PUCHAR>(const_cast<char*>(bootstrap.api_origin.data())),
      static_cast<ULONG>(bootstrap.api_origin.size()), digest, sizeof(digest)) == 0);
  // This NodeEntry is storage-only: derived ID is never an API node ID and
  // never leaves this file.
  node_session::detail::NodeEntry key;
  constexpr char hex[] = "0123456789abcdef";
  key.node_id.reserve(64);
  for (auto c : digest) {key.node_id += hex[c >> 4]; key.node_id += hex[c & 15];}
  key.name = bootstrap.api_origin; // Exact origin, including explicit :443.
  return key;
}
} // namespace

void CredentialStore::save(const PlatformConfig& config, const Session& session) {
  const auto key = storage_key(config);
  Directory directory(StoreKind::platform);
  NodeLock lock(directory, key, false);
  require_not_pending(directory, key);
  const auto envelope = session.export_envelope();
  credential_detail::validate_envelope(config.api_origin(), envelope.view(), now());
  const auto blob = encrypt(envelope.view(), directory.scope(key));
  atomic_write(directory, key, blob);
}
Session CredentialStore::load(const PlatformConfig& config) {
  const auto key = storage_key(config);
  Directory directory(StoreKind::platform);
  NodeLock lock(directory, key, false);
  require_not_pending(directory, key);
  auto file = directory.open(key);
  checked(file != nullptr);
  try {
    verify_object(file.get(), false); verify_acl(file.get(), directory.user, false);
    LARGE_INTEGER size{};
    checked(GetFileSizeEx(file.get(), &size) != FALSE && size.QuadPart > 0 && size.QuadPart <= 65536);
    Secret encrypted{std::string(static_cast<std::size_t>(size.QuadPart), '\0')};
    DWORD count = 0;
    checked(ReadFile(file.get(), encrypted.bytes.data(), static_cast<DWORD>(encrypted.bytes.size()), &count, nullptr) != FALSE && count == encrypted.bytes.size());
    directory.verify(); verify_acl(file.get(), directory.user, false);
    const auto plaintext = decrypt(encrypted.bytes, directory.scope(key));
    const std::string_view envelope(reinterpret_cast<const char*>(plaintext.value.pbData), plaintext.value.cbData);
    credential_detail::validate_envelope(config.api_origin(), envelope, now());
    return Session::restore(config, envelope);
  } catch (...) {
    file.reset();
    // Invalid/expired/revoked credentials use the existing durable transaction.
    // Any failure leaves its marker intact; never hide the original failure.
    try {erase_pending(directory, key);} catch (...) {}
    throw;
  }
}
void CredentialStore::erase(const PlatformConfig& config) {
  const auto key = storage_key(config);
  Directory directory(StoreKind::platform);
  NodeLock lock(directory, key);
  erase_pending(directory, key);
}
} // namespace orangespace::platform_session
#endif
