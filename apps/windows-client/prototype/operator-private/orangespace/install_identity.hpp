#pragma once
// PRIVATE to the separately compiled service_client_win.cpp object only.
// Do not place this directory on credential-store or legacy UI include paths.
// Rename the namespace in this TU to avoid ODR collisions with the SDK's real
// installation identity used by ordinary-user DPAPI persistence.
#define install_identity prototype_operator_install_identity
namespace orangespace::prototype_operator_install_identity {
inline constexpr wchar_t service_name[]=L"OrangeSpaceSinglePrototype.SG.v25";
inline constexpr wchar_t pipe_prefix[]=L"\\\\.\\pipe\\OrangeSpace.SinglePrototype.SG.v25.Control.v1.session.";
}
