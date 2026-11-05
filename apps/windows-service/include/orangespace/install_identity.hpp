#pragma once
#include <string_view>
#ifndef ORANGESPACE_DEVELOPMENT_INSTALL_ID
#define ORANGESPACE_DEVELOPMENT_INSTALL_ID ""
#endif
#define ORANGESPACE_ID_WIDE_(x) L##x
#define ORANGESPACE_ID_WIDE(x) ORANGESPACE_ID_WIDE_(x)
namespace orangespace::install_identity {
inline constexpr std::string_view suffix = ORANGESPACE_DEVELOPMENT_INSTALL_ID;
constexpr bool valid_suffix() {
    if (suffix.size() > 24) return false;
    for (const char c : suffix)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    return true;
}
static_assert(valid_suffix(), "Invalid development install identity");
// Both names point into the same embedded provenance record. No runtime override.
inline constexpr wchar_t default_record[] =
    L"OrangeSpace.InstallIdentity.v1||OrangeSpaceFoundation\0\\\\.\\pipe\\OrangeSpace.Foundation.v1.session.";
inline constexpr wchar_t dev_record[] =
    L"OrangeSpace.InstallIdentity.v1|" ORANGESPACE_ID_WIDE(ORANGESPACE_DEVELOPMENT_INSTALL_ID)
    L"|OrangeSpaceFoundation.Dev." ORANGESPACE_ID_WIDE(ORANGESPACE_DEVELOPMENT_INSTALL_ID)
    L"\0\\\\.\\pipe\\OrangeSpace.Foundation.Dev." ORANGESPACE_ID_WIDE(ORANGESPACE_DEVELOPMENT_INSTALL_ID) L".v1.session.";
inline constexpr auto record = suffix.empty() ? default_record : dev_record;
inline constexpr auto service_name = record + std::wstring_view(L"OrangeSpace.InstallIdentity.v1|").size() + suffix.size() + 1;
inline constexpr auto pipe_prefix = service_name + std::wstring_view(L"OrangeSpaceFoundation").size() + (suffix.empty() ? 0 : 5 + suffix.size()) + 1;
}
#undef ORANGESPACE_ID_WIDE
#undef ORANGESPACE_ID_WIDE_
