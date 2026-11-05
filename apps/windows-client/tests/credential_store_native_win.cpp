// Standalone native implementation test: compile this TU (which includes the
// implementation for private-seam tests) plus node_session_win.cpp; do NOT also
// link credential_store_win.cpp. Requires a limited interactive user's token.
#include "../src/credential_store_win.cpp"
#include <iostream>
#include <type_traits>
#ifdef _WIN32
namespace ns = orangespace::node_session;
static_assert(!std::is_copy_constructible_v<ns::Blob>, "DPAPI allocation must have one wiping owner");
static_assert(std::is_move_constructible_v<ns::Blob>);
int main() {
  try {
    ns::Directory directory;
    unsigned char random[16]{};
    if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) return 2;
    std::string id;
    constexpr char hex[] = "0123456789abcdef";
    for (auto c : random) { id += hex[c >> 4]; id += hex[c & 15]; }
    for (auto p : {8u, 13u, 18u, 23u}) id.insert(p, "-");
    const ns::detail::NodeEntry node{"fixture", id, "node.example", 443};
    struct RemoveFixture {
      ns::Directory& directory; const ns::detail::NodeEntry& node;
      ~RemoveFixture() { try { auto file = directory.open(node); if (file) ns::purge(file.get()); } catch (...) {} }
    } cleanup{directory, node};
    const auto scope = directory.scope(node);
    const std::string clear = "not-a-real-credential/test-fixture";
    const auto encrypted = ns::encrypt(clear, scope);
    std::string bytes(reinterpret_cast<char*>(encrypted.value.pbData), encrypted.value.cbData);
    const auto decrypted = ns::decrypt(bytes, scope);
    if (std::string_view(reinterpret_cast<char*>(decrypted.value.pbData), decrypted.value.cbData) != clear) return 3;
    bool denied = false;
    try { (void)ns::decrypt(bytes, scope + "wrong"); } catch (...) { denied = true; }
    if (!denied) return 4;
    bytes.back() ^= 1;
    denied = false;
    try { (void)ns::decrypt(bytes, scope); } catch (...) { denied = true; }
    if (!denied) return 5;
    ns::atomic_write(directory, node, encrypted);
    ns::atomic_write(directory, node, encrypted); // Real same-volume replacement.
    auto file = directory.open(node);
    if (!file) return 6;
    ns::verify_object(file.get(), false); ns::verify_acl(file.get(), directory.user, false);
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file.get(), &length) || length.QuadPart != encrypted.value.cbData) return 8;
    std::string readback(encrypted.value.cbData, '\0'); DWORD count = 0;
    if (!ReadFile(file.get(), readback.data(), static_cast<DWORD>(readback.size()), &count, nullptr) ||
        count != readback.size() || std::memcmp(readback.data(), encrypted.value.pbData, count)) return 9;
    // Probe rename denial on an isolated child, never the user's product root.
    const auto held_path = directory.path + L"\\hold-" + std::wstring(id.begin(), id.end());
    if (!CreateDirectoryW(held_path.c_str(), &directory.attributes)) return 10;
    struct RemoveDirectoryFixture {
      std::wstring path; ~RemoveDirectoryFixture() { RemoveDirectoryW(path.c_str()); RemoveDirectoryW((path + L"-moved").c_str()); }
    } remove_directory{held_path};
    ns::Handle held(CreateFileW(held_path.c_str(), READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    if (held.get() == INVALID_HANDLE_VALUE) return 11;
    if (MoveFileExW(held_path.c_str(), (held_path + L"-moved").c_str(), 0)) return 12;
    held.reset();
    if (!RemoveDirectoryW(held_path.c_str())) return 13;
    const auto absent = GetFileAttributesW(held_path.c_str());
    const auto absent_error = GetLastError();
    if (absent != INVALID_FILE_ATTRIBUTES || (absent_error != ERROR_FILE_NOT_FOUND && absent_error != ERROR_PATH_NOT_FOUND)) return 14;
    // Deliberately weaken only this random fixture's ACL and require the held
    // handle validator to reject another principal's read access.
    PSECURITY_DESCRIPTOR bad_descriptor = nullptr;
    const auto bad_sddl = L"D:P(A;;FA;;;SY)(A;;FA;;;" + directory.user.sid_text + L")(A;;FR;;;WD)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(bad_sddl.c_str(), SDDL_REVISION_1, &bad_descriptor, nullptr)) return 15;
    ns::Local bad_storage(bad_descriptor);
    PACL bad_acl = nullptr; BOOL present = FALSE, defaulted = FALSE;
    if (!GetSecurityDescriptorDacl(bad_descriptor, &present, &bad_acl, &defaulted)) return 16;
    const auto fixture_path = directory.path + L"\\" + directory.filename(node);
    ns::Handle edit(CreateFileW(fixture_path.c_str(), WRITE_DAC | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (edit.get() == INVALID_HANDLE_VALUE) {
      std::cerr << "native ACL injection open failed: win32=" << GetLastError() << '\n'; return 17;
    }
    const auto changed = SetSecurityInfo(edit.get(), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, bad_acl, nullptr);
    if (changed != ERROR_SUCCESS) {
      std::cerr << "native ACL injection set failed: win32=" << changed << '\n'; return 17;
    }
    denied = false;
    try { ns::verify_acl(file.get(), directory.user, false); } catch (...) { denied = true; }
    if (!denied) return 18;
    edit.reset();
    ns::purge(file.get()); file.reset();
    if (directory.open(node)) return 7;
    directory.verify();
    std::cout << "native user DPAPI, wrong scope, tamper, held ACL and atomic write/delete: passed\n";
    return 0;
  } catch (...) { std::cerr << "native credential primitive test failed\n"; return 1; }
}
#endif
