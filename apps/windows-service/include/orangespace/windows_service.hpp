#pragma once
#include "orangespace/service_policy.hpp"
#include <windows.h>
#include <utility>
#include <vector>
namespace orangespace::service::win {
class Handle {
    HANDLE value_{};
public:
    explicit Handle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~Handle() { if (*this) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) { if (*this) CloseHandle(value_); value_ = std::exchange(other.value_, nullptr); }
        return *this;
    }
    HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
};
[[noreturn]] void fail(const char* operation);
Peer token_peer(HANDLE token);
Peer current_peer();
Handle create_pipe(const std::wstring& name, const Peer& expected);
bool connect_pipe(HANDLE pipe, HANDLE stop);
bool serve_connection(HANDLE pipe, const Peer& expected, HANDLE stop);

// No copies, no stream/log conversion. DPAPI plaintext memory is wiped before LocalFree.
class Secret {
    BYTE* data_{};
    DWORD size_{};
public:
    Secret(BYTE* data, DWORD size) noexcept : data_(data), size_(size) {}
    ~Secret();
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&& other) noexcept : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}
    Secret& operator=(Secret&&) = delete;
    std::span<const std::uint8_t> bytes() const noexcept { return {data_, size_}; }
};
// Must run under an interactive user's token/profile, never SYSTEM/machine scope.
// scope is a public, stable credential purpose/node identifier, not a secret.
std::vector<std::uint8_t> protect_credential(std::span<const std::uint8_t> secret, std::string_view scope);
Secret unprotect_credential(std::span<const std::uint8_t> encrypted, std::string_view scope);
}
