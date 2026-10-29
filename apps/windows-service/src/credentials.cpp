#include "orangespace/windows_service.hpp"
#include <dpapi.h>
#include <stdexcept>
namespace orangespace::service::win {
Secret::~Secret() {
    if (data_) { SecureZeroMemory(data_, size_); LocalFree(data_); }
}
static std::string entropy_for(std::string_view scope) {
    const Peer peer = current_peer();
    if (!peer.session || !pipe_sddl(peer.sid)) throw std::runtime_error("DPAPI requires interactive user context");
    if (scope.empty() || scope.size() > 256 || !std::all_of(scope.begin(), scope.end(),
        [](unsigned char c) { return c >= 33 && c <= 126; })) throw std::invalid_argument("invalid credential scope");
    return "OrangeSpace/credential/v1/" + peer.sid + "/" + std::string(scope);
}
std::vector<std::uint8_t> protect_credential(std::span<const std::uint8_t> secret, std::string_view scope) {
    if (secret.empty() || secret.size() > 4096) throw std::invalid_argument("credential size");
    auto entropy = entropy_for(scope);
    DATA_BLOB in{static_cast<DWORD>(secret.size()), const_cast<BYTE*>(secret.data())};
    DATA_BLOB extra{static_cast<DWORD>(entropy.size()), reinterpret_cast<BYTE*>(entropy.data())};
    DATA_BLOB out{};
    // Intentionally no CRYPTPROTECT_LOCAL_MACHINE and no UI. Failure has no plaintext fallback.
    if (!CryptProtectData(&in, L"OrangeSpace credential v1", &extra, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        fail("CryptProtectData");
    struct Free { BYTE* p; ~Free() { LocalFree(p); } } free_blob{out.pbData};
    return {out.pbData, out.pbData + out.cbData};
}
Secret unprotect_credential(std::span<const std::uint8_t> encrypted, std::string_view scope) {
    if (encrypted.empty() || encrypted.size() > 16384) throw std::invalid_argument("protected credential size");
    auto entropy = entropy_for(scope);
    DATA_BLOB in{static_cast<DWORD>(encrypted.size()), const_cast<BYTE*>(encrypted.data())};
    DATA_BLOB extra{static_cast<DWORD>(entropy.size()), reinterpret_cast<BYTE*>(entropy.data())};
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, &extra, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        fail("CryptUnprotectData");
    Secret plaintext(out.pbData, out.cbData);
    if (plaintext.bytes().empty() || plaintext.bytes().size() > 4096) throw std::runtime_error("unprotected credential size");
    return plaintext;
}
}
