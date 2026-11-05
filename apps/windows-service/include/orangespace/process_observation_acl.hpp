#pragma once
#include "orangespace/windows_service.hpp"
#include <sddl.h>
#include <cstring>
#include <set>
#include <map>
#include <stdexcept>

namespace orangespace::service::win {
// A single service-thread owner, bound to this process for its whole lifetime.
// Only the initial DACL is a policy source; published ACLs are never merged.
class ProcessObservationAcl {
    static constexpr SECURITY_INFORMATION query_info =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    static constexpr DWORD observation = PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
    std::vector<BYTE> baseline_;
    std::vector<BYTE> expected_;
    bool failed_{};

    static std::vector<BYTE> read() {
        DWORD size{};
        if (GetKernelObjectSecurity(GetCurrentProcess(), query_info, nullptr, 0, &size) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || !size || size > 65536)
            fail("size process security");
        std::vector<BYTE> result(size);
        if (!GetKernelObjectSecurity(GetCurrentProcess(), query_info, result.data(), size, &size))
            fail("read process security");
        result.resize(size);
        return result;
    }
    static PACL dacl(const std::vector<BYTE>& sd) {
        PACL acl{};
        BOOL present{}, defaulted{};
        if (!IsValidSecurityDescriptor(const_cast<BYTE*>(sd.data())) ||
            !GetSecurityDescriptorDacl(const_cast<BYTE*>(sd.data()), &present, &acl, &defaulted) ||
            !present || !acl || !IsValidAcl(acl))
            throw std::runtime_error("unsupported absent/null process DACL");
        return acl;
    }
    static SECURITY_DESCRIPTOR_CONTROL control(const std::vector<BYTE>& sd) {
        SECURITY_DESCRIPTOR_CONTROL bits{};
        DWORD revision{};
        if (!GetSecurityDescriptorControl(const_cast<BYTE*>(sd.data()), &bits, &revision))
            fail("process security control");
        return bits;
    }
    static bool same_identity_and_control(const std::vector<BYTE>& a, const std::vector<BYTE>& b) {
        PSID ao{}, bo{}, ag{}, bg{};
        BOOL unused{};
        if (!GetSecurityDescriptorOwner(const_cast<BYTE*>(a.data()), &ao, &unused) ||
            !GetSecurityDescriptorOwner(const_cast<BYTE*>(b.data()), &bo, &unused) ||
            !GetSecurityDescriptorGroup(const_cast<BYTE*>(a.data()), &ag, &unused) ||
            !GetSecurityDescriptorGroup(const_cast<BYTE*>(b.data()), &bg, &unused)) fail("process owner/group");
        return ao && bo && ag && bg && EqualSid(ao, bo) && EqualSid(ag, bg) && control(a) == control(b);
    }
public:
    ProcessObservationAcl() : baseline_(read()), expected_(baseline_) {
        const auto acl = dacl(baseline_);
        // Object/callback/conditional and unknown ACEs need separate semantics;
        // never guess at them. Ordinary inherited deny/allow ACEs are retained.
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void* raw{};
            if (!GetAce(acl, i, &raw)) fail("read process ACE");
            const auto ace = static_cast<ACE_HEADER*>(raw);
            if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE && ace->AceType != ACCESS_DENIED_ACE_TYPE)
                throw std::runtime_error("unsupported process ACE");
        }
    }
    ProcessObservationAcl(const ProcessObservationAcl&) = delete;
    ProcessObservationAcl& operator=(const ProcessObservationAcl&) = delete;
    void publish(const std::map<DWORD, Peer>& peers) {
        if (failed_) throw std::runtime_error("process ACL publisher failed closed");
        failed_ = true; // Any error permanently poisons this publisher; service exits.
        if (read() != expected_) throw std::runtime_error("external process security change");
        std::set<std::string> sids;
        for (const auto& [session, peer] : peers) {
            (void)session;
            if (!pipe_sddl(peer.sid)) throw std::runtime_error("invalid OS SID");
            sids.insert(peer.sid); // User-wide, across logons; NOT pipe authorization.
        }
        if (sids.size() > 64) throw std::runtime_error("too many process observation SIDs");
        const auto original = dacl(baseline_);
        ACL_SIZE_INFORMATION info{};
        if (!GetAclInformation(original, &info, sizeof(info), AclSizeInformation)) fail("process ACL size");
        // Maximum SID length bounds allocation; ACL size is a WORD in the SDK.
        const auto size = info.AclBytesInUse + sids.size() * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + SECURITY_MAX_SID_SIZE);
        if (size > 65535) throw std::runtime_error("process observation ACL too large");
        std::vector<BYTE> storage(size);
        const auto next = reinterpret_cast<PACL>(storage.data());
        if (!InitializeAcl(next, static_cast<DWORD>(size), original->AclRevision)) fail("initialize process ACL");
        for (DWORD i = 0; i < original->AceCount; ++i) {
            void* raw{};
            if (!GetAce(original, i, &raw) ||
                !AddAce(next, original->AclRevision, MAXDWORD, raw, static_cast<ACE_HEADER*>(raw)->AceSize))
                fail("copy baseline process ACE");
        }
        // Append AFTER every original ACE, including inherited denies. Do not
        // canonicalize: moving this allow before an inherited deny weakens it.
        for (const auto& sid : sids) {
            PSID raw{};
            if (!ConvertStringSidToSidA(sid.c_str(), &raw)) fail("observation SID");
            const bool ok = AddAccessAllowedAceEx(next, original->AclRevision, 0, observation, raw);
            LocalFree(raw);
            if (!ok) fail("append process observation ACE");
        }
        const auto previous = dacl(expected_);
        ACL_SIZE_INFORMATION previous_info{}, next_info{};
        if (!GetAclInformation(previous, &previous_info, sizeof(previous_info), AclSizeInformation) ||
            !GetAclInformation(next, &next_info, sizeof(next_info), AclSizeInformation)) fail("compare process ACL");
        // Ignore allocation/free padding, but compare the complete ACE stream.
        const auto ace_bytes = next_info.AclBytesInUse - sizeof(ACL);
        if (previous_info.AclBytesInUse == next_info.AclBytesInUse &&
            previous->AceCount == next->AceCount &&
            std::memcmp(reinterpret_cast<BYTE*>(previous) + sizeof(ACL), storage.data() + sizeof(ACL), ace_bytes) == 0) {
            failed_ = false;
            return;
        }
        SECURITY_DESCRIPTOR sd{};
        BOOL present{}, defaulted{};
        PACL unused{};
        if (!GetSecurityDescriptorDacl(baseline_.data(), &present, &unused, &defaulted) ||
            !InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) ||
            !SetSecurityDescriptorDacl(&sd, TRUE, next, defaulted)) fail("prepare process DACL");
        constexpr SECURITY_DESCRIPTOR_CONTROL mask = SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ;
        if (!SetSecurityDescriptorControl(&sd, mask, control(baseline_) & mask)) fail("preserve DACL control");
        // No owner/group/SACL update. Recheck immediately before the write.
        // Windows offers no DACL compare-and-swap against a concurrent privileged writer.
        if (read() != expected_) throw std::runtime_error("external process security change before write");
        if (!SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, &sd)) fail("publish process DACL");
        auto actual = read();
        const auto actual_acl = dacl(actual);
        ACL_SIZE_INFORMATION actual_info{};
        if (!GetAclInformation(actual_acl, &actual_info, sizeof(actual_info), AclSizeInformation) ||
            !same_identity_and_control(baseline_, actual) || actual_acl->AceCount != next->AceCount ||
            actual_info.AclBytesInUse != next_info.AclBytesInUse ||
            std::memcmp(reinterpret_cast<BYTE*>(actual_acl) + sizeof(ACL), storage.data() + sizeof(ACL), ace_bytes) != 0)
            throw std::runtime_error("process DACL publication readback mismatch");
        expected_ = std::move(actual);
        failed_ = false;
    }
};
}
