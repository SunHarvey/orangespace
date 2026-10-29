#include "orangespace/node_session.hpp"

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <winhttp.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <memory>
#include <system_error>

namespace orangespace::node_session {
namespace {
[[noreturn]] void fail(const char* message) { throw std::runtime_error(message); }
void checked(BOOL ok, const char* message) { if (!ok) fail(message); }
struct FileClose { void operator()(void* h) const noexcept { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); } };
struct InternetClose { void operator()(void* h) const noexcept { if (h) WinHttpCloseHandle(h); } };
struct LocalClose { void operator()(void* p) const noexcept { if (p) LocalFree(p); } };
using File = std::unique_ptr<void, FileClose>;
using Internet = std::unique_ptr<void, InternetClose>;
using Local = std::unique_ptr<void, LocalClose>;
struct SecretBytes {
  std::vector<char> bytes;
  ~SecretBytes() { detail::wipe(bytes.data(), bytes.size()); }
  SecretBytes() = default;
  SecretBytes(const SecretBytes&) = delete;
  SecretBytes& operator=(const SecretBytes&) = delete;
  SecretBytes(SecretBytes&&) = default;
  std::string_view view() const { return {bytes.data(), bytes.size()}; }
};
struct SecretText {
  std::string text;
  ~SecretText() { detail::wipe(text.data(), text.size()); }
};
struct SecretWide {
  std::wstring text;
  ~SecretWide() { detail::wipe(text.data(), text.size() * sizeof(wchar_t)); }
};
bool privileged(PSID sid, bool ancestor) {
  if (!sid || !IsValidSid(sid)) return false;
  if (IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) return true;
  if (!ancestor) return false;
  // Windows drive roots can be owned by the TrustedInstaller service. It is
  // accepted for ancestors only, never for the catalog or its immediate parent.
  PSID ti = nullptr;
  checked(ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti), "cannot resolve system trust owner");
  Local owner(ti);
  return EqualSid(sid, ti) != FALSE;
}
void verify_acl(HANDLE handle, bool ancestor) {
  PSID owner = nullptr;
  PACL acl = nullptr;
  PSECURITY_DESCRIPTOR raw = nullptr;
  if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                      &owner, nullptr, &acl, nullptr, &raw) != ERROR_SUCCESS) fail("cannot read trust ACL");
  Local descriptor(raw);
  SECURITY_DESCRIPTOR_CONTROL control{};
  DWORD revision = 0;
  checked(GetSecurityDescriptorControl(raw, &control, &revision), "cannot inspect trust ACL");
  std::vector<detail::Ace> entries;
  if (acl) {
    checked(IsValidAcl(acl), "invalid trust ACL");
    for (DWORD i = 0; i < acl->AceCount; ++i) {
      void* raw_ace = nullptr;
      checked(GetAce(acl, i, &raw_ace), "invalid trust ACE");
      const auto* header = static_cast<const ACE_HEADER*>(raw_ace);
      if (header->AceFlags & INHERIT_ONLY_ACE) continue; // Not effective on this object.
      if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
        entries.push_back({detail::AceKind::allow, privileged(const_cast<DWORD*>(&ace->SidStart), ancestor), ace->Mask});
      } else if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
        entries.push_back({detail::AceKind::deny, false, 0});
      } else entries.push_back({detail::AceKind::unsupported, false, 0});
    }
  }
  if (!detail::secure_acl(privileged(owner, ancestor), (control & SE_DACL_PROTECTED) != 0,
                          (control & SE_DACL_PRESENT) != 0 && acl != nullptr, entries, ancestor))
    fail("trust path is not administrator protected");
}
std::string read_catalog(const std::wstring& path) {
  if (!detail::explicit_local_path(path)) fail("trust path must be an explicit local absolute path");
  const std::wstring root = path.substr(0, 3);
  if (GetDriveTypeW(root.c_str()) != DRIVE_FIXED) fail("trust must reside on a local fixed drive");
  DWORD volume_flags = 0;
  checked(GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, &volume_flags, nullptr, 0), "cannot inspect trust volume");
  if (!(volume_flags & FS_PERSISTENT_ACLS)) fail("trust volume does not support persistent ACLs");
  std::vector<std::wstring> parts{root};
  for (std::size_t pos = path.find(L'\\', 3); pos != std::wstring::npos; pos = path.find(L'\\', pos + 1))
    parts.push_back(path.substr(0, pos));
  parts.push_back(path);
  std::vector<File> handles;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    const bool leaf = i + 1 == parts.size();
    const DWORD access = READ_CONTROL | FILE_READ_ATTRIBUTES | (leaf ? FILE_READ_DATA : 0);
    File handle(CreateFileW(parts[i].c_str(), access, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (handle.get() == INVALID_HANDLE_VALUE) fail("cannot open protected trust path");
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    checked(GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo, &attributes, sizeof(attributes)), "cannot inspect trust path");
    if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        (leaf ? (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 : (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0))
      fail("trust path contains a reparse point or invalid object");
    verify_acl(handle.get(), i + 2 < parts.size());
    handles.push_back(std::move(handle)); // Hold ancestors against rename/delete through the read.
  }
  LARGE_INTEGER length{};
  checked(GetFileSizeEx(handles.back().get(), &length), "cannot read trust size");
  if (length.QuadPart <= 0 || length.QuadPart > 65536) fail("invalid trust file size");
  std::string data(static_cast<std::size_t>(length.QuadPart), '\0');
  DWORD read = 0;
  checked(ReadFile(handles.back().get(), data.data(), static_cast<DWORD>(data.size()), &read, nullptr), "cannot read trust configuration");
  if (read != data.size()) fail("incomplete trust configuration");
  // Verify again after reading from the same handle, not by reopening the path.
  for (std::size_t i = 0; i < handles.size(); ++i) verify_acl(handles[i].get(), i + 2 < handles.size());
  return data;
}
std::wstring ascii_wide(std::string_view value) { return {value.begin(), value.end()}; }
std::string unique_header(HINTERNET request, DWORD query, const wchar_t* name) {
  std::array<wchar_t, 256> buffer{};
  DWORD size = static_cast<DWORD>(buffer.size() * sizeof(wchar_t));
  DWORD index = 0;
  checked(WinHttpQueryHeaders(request, query, name, buffer.data(), &size, &index), "missing or oversized response header");
  std::string result;
  for (std::size_t i = 0; i < size / sizeof(wchar_t); ++i) {
    if (buffer[i] < 32 || buffer[i] > 126) fail("invalid response header");
    result.push_back(static_cast<char>(buffer[i]));
  }
  size = static_cast<DWORD>(buffer.size() * sizeof(wchar_t));
  if (WinHttpQueryHeaders(request, query, name, buffer.data(), &size, &index) || GetLastError() != ERROR_WINHTTP_HEADER_NOT_FOUND)
    fail("duplicate response header");
  return result;
}
struct Response {
  unsigned status{};
  std::string node;
  SecretBytes body;
};
class Transport {
 public:
  explicit Transport(const detail::NodeEntry& node)
      : session_(WinHttpOpen(L"OrangeSpace-Login/0.1", WINHTTP_ACCESS_TYPE_NO_PROXY,
                             WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)) {
    if (!session_) fail("cannot initialize HTTPS");
    checked(WinHttpSetTimeouts(session_.get(), 5000, 5000, 5000, 5000), "cannot set HTTPS timeouts");
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#ifdef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
    protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
    checked(WinHttpSetOption(session_.get(), WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols)), "cannot require modern TLS");
    connection_.reset(WinHttpConnect(session_.get(), ascii_wide(node.host).c_str(), node.port, 0));
    if (!connection_) fail("cannot initialize pinned origin");
  }
  Response request(const wchar_t* method, const wchar_t* path, std::string_view body = {}, std::string_view token = {}) {
    const auto started = GetTickCount64();
    Internet request(WinHttpOpenRequest(connection_.get(), method, path, nullptr, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
    if (!request) fail("cannot initialize HTTPS request");
    DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    checked(WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy)), "cannot disable redirects");
    DWORD disable = WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
    checked(WinHttpSetOption(request.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable)), "cannot disable ambient authentication");
    DWORD revocation = WINHTTP_ENABLE_SSL_REVOCATION;
    checked(WinHttpSetOption(request.get(), WINHTTP_OPTION_ENABLE_FEATURE, &revocation, sizeof(revocation)), "cannot enable certificate revocation checking");
    DWORD header_limit = 16384;
    checked(WinHttpSetOption(request.get(), WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, &header_limit, sizeof(header_limit)), "cannot bound HTTPS headers");
    // Never set SECURITY_FLAG_IGNORE_* or supply an insecure certificate callback.
    SecretWide headers;
    headers.text.reserve(256);
    headers.text = L"Accept: application/json\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n";
    if (!token.empty()) { headers.text += L"Authorization: Bearer "; headers.text.append(token.begin(), token.end()); headers.text += L"\r\n"; }
    if (body.size() > 16384) fail("credential request exceeds limit");
    if (!WinHttpSendRequest(request.get(), headers.text.c_str(), static_cast<DWORD>(headers.text.size()),
                            body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
                            static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0)) {
      // Preserve the native error before WinHTTP handle cleanup overwrites it.
      // The exception contains only a constant operation and OS error, no body,
      // authorization header, response data or credential material.
      const DWORD error = GetLastError();
      throw std::system_error(static_cast<int>(error), std::system_category(), "HTTPS send failed");
    }
    checked(WinHttpReceiveResponse(request.get(), nullptr), "HTTPS response failed");
    Response response;
    DWORD status = 0, size = sizeof(status);
    checked(WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX), "cannot inspect HTTPS status");
    response.status = status;
    response.node = unique_header(request.get(), WINHTTP_QUERY_CUSTOM, L"X-OrangeSpace-Node");
    const auto content_type = unique_header(request.get(), WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX);
    if (content_type != "application/json" && content_type != "application/json; charset=utf-8") fail("response is not JSON");
    response.body.bytes.reserve(16384);
    struct ReadBuffer { std::array<char, 4096> data{}; ~ReadBuffer() { detail::wipe(data.data(), data.size()); } } buffer;
    while (true) {
      if (GetTickCount64() - started > 30000) fail("HTTPS response deadline exceeded");
      DWORD count = 0;
      checked(WinHttpReadData(request.get(), buffer.data.data(), static_cast<DWORD>(buffer.data.size()), &count), "HTTPS read failed");
      if (!count) break;
      if (count > 16384 - response.body.bytes.size()) fail("HTTPS response exceeds limit");
      response.body.bytes.insert(response.body.bytes.end(), buffer.data.begin(), buffer.data.begin() + count);
    }
    return response;
  }
 private:
  Internet session_;
  Internet connection_;
};
void append_json_string(std::string& output, std::string_view input) {
  constexpr char hex[] = "0123456789abcdef";
  output += '"';
  for (unsigned char c : input) {
    if (c == '"' || c == '\\') { output += '\\'; output += static_cast<char>(c); }
    else if (c < 32) { output += "\\u00"; output += hex[c >> 4]; output += hex[c & 15]; }
    else output += static_cast<char>(c);
  }
  output += '"';
}
std::int64_t now_seconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}
} // namespace

TrustedCatalog TrustedCatalog::load(const std::wstring& explicit_path) {
  return TrustedCatalog(detail::parse_catalog(read_catalog(explicit_path)));
}
std::vector<std::string> TrustedCatalog::names() const {
  std::vector<std::string> result;
  for (const auto& node : nodes_) result.push_back(node.name);
  return result;
}
NodeSession NodeSession::login(const TrustedCatalog& catalog, std::string_view name,
                               std::string_view username, std::string_view password) {
  const auto found = std::find_if(catalog.nodes_.begin(), catalog.nodes_.end(), [&](const auto& node) { return node.name == name; });
  if (found == catalog.nodes_.end()) fail("node alias is not administrator pinned");
  if (username.empty() || username.size() > 256 || !detail::safe_utf8(username, true) ||
      password.empty() || password.size() > 4096 || !detail::safe_utf8(password)) fail("invalid credential input");
  Transport transport(*found);
  // No credentials have been sent yet. Require the platform-validated HTTPS
  // origin to assert the pinned node before posting a password to /v1/auth/login.
  auto preflight = transport.request(L"GET", L"/healthz");
  if (preflight.status != 200 || preflight.node != found->node_id) fail("trusted node preflight failed");
  SecretText body;
  body.text.reserve(16384);
  body.text = "{\"username\":";
  append_json_string(body.text, username);
  body.text += ",\"password\":";
  append_json_string(body.text, password);
  body.text += '}';
  auto response = transport.request(L"POST", L"/v1/auth/login", body.text);
  detail::wipe(body.text.data(), body.text.size());
  body.text.clear();
  const auto login = detail::validate_login(*found, response.status, response.node, response.body.view(), now_seconds());
  auto me_response = transport.request(L"GET", L"/v1/me", {}, login.token);
  auto identity = detail::validate_me(*found, me_response.status, me_response.node, me_response.body.view());
  if (login.expires_at <= now_seconds()) fail("session expired during authentication");
  return NodeSession(*found, std::move(identity), login);
}
} // namespace orangespace::node_session
#endif
