// Narrow Linux-only type/API shim for extracted native rule predicates.
// No BFE/engine/process emulation. Real SDK compilation is a separate gate.
#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include "network_policy_win.hpp"
using BYTE=std::uint8_t; using DWORD=std::uint32_t;
using UINT32=std::uint32_t; using UINT64=std::uint64_t;
struct GUID { DWORD Data1; std::uint16_t Data2,Data3; BYTE Data4[8]; };
inline bool IsEqualGUID(const GUID& a,const GUID& b) { return !std::memcmp(&a,&b,sizeof(a)); }
struct SID_IDENTIFIER_AUTHORITY { BYTE Value[6]; };
struct SID { BYTE Revision,SubAuthorityCount; SID_IDENTIFIER_AUTHORITY IdentifierAuthority; DWORD SubAuthority[1]; };
using PSID=void*;
#define SECURITY_APP_PACKAGE_AUTHORITY {0,0,0,0,0,15}
constexpr DWORD SECURITY_APP_PACKAGE_BASE_RID=2, ERROR_INVALID_DATA=13;
inline bool IsValidSid(PSID s) { return s && static_cast<SID*>(s)->Revision==1 && static_cast<SID*>(s)->SubAuthorityCount<=15; }
inline BYTE* GetSidSubAuthorityCount(PSID s) {return &static_cast<SID*>(s)->SubAuthorityCount;}
inline SID_IDENTIFIER_AUTHORITY* GetSidIdentifierAuthority(PSID s) {return &static_cast<SID*>(s)->IdentifierAuthority;}
inline DWORD* GetSidSubAuthority(PSID s,DWORD n) {return reinterpret_cast<DWORD*>(static_cast<BYTE*>(s)+8)+n;}
inline DWORD GetSidLengthRequired(BYTE n) {return 8+4*n;}
inline DWORD GetLengthSid(PSID s) {return GetSidLengthRequired(*GetSidSubAuthorityCount(s));}
inline bool EqualSid(PSID a,PSID b) {return IsValidSid(a)&&IsValidSid(b)&&GetLengthSid(a)==GetLengthSid(b)&&!std::memcmp(a,b,GetLengthSid(a));}
struct FWP_BYTE_BLOB {UINT32 size; BYTE* data;};
enum {FWP_UINT8=1,FWP_UINT16,FWP_UINT32,FWP_UINT64,FWP_BYTE_BLOB_TYPE,FWP_SID};
enum {FWP_MATCH_EQUAL,FWP_MATCH_NOT_EQUAL};
constexpr UINT32 FWPM_FILTER_FLAG_PERSISTENT=1, FWPM_FILTER_FLAG_INDEXED=2;
constexpr UINT32 FWP_ACTION_BLOCK=1, FWP_ACTION_PERMIT=2;
struct FWP_CONDITION_VALUE0 {
 int type=0;
 union {BYTE uint8; std::uint16_t uint16; UINT32 uint32; UINT64* uint64; FWP_BYTE_BLOB* byteBlob; SID* sid;};
};
struct FWPM_FILTER_CONDITION0 {GUID fieldKey{}; int matchType=0; FWP_CONDITION_VALUE0 conditionValue{};};
struct FWPM_FILTER0 {
 GUID filterKey{}; GUID* providerKey=nullptr; GUID subLayerKey{},layerKey{};
 UINT32 flags=0; struct {wchar_t* name=nullptr;} displayData;
 struct {UINT32 type=0;} action;
 FWP_CONDITION_VALUE0 weight{};
 FWPM_FILTER_CONDITION0* filterCondition=nullptr; UINT32 numFilterConditions=0;
 UINT64 filterId=0; FWP_BYTE_BLOB providerData{}; UINT64 rawContext=0;
};
inline const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4={1,0,0,{}},
 FWPM_LAYER_ALE_AUTH_CONNECT_V6={2,0,0,{}}, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4={3,0,0,{}},
 FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6={4,0,0,{}};
inline const GUID FWPM_CONDITION_ALE_APP_ID={5,0,0,{}}, FWPM_CONDITION_ALE_PACKAGE_ID={6,0,0,{}},
 FWPM_CONDITION_IP_PROTOCOL={7,0,0,{}}, FWPM_CONDITION_IP_REMOTE_ADDRESS={8,0,0,{}},
 FWPM_CONDITION_IP_REMOTE_PORT={9,0,0,{}};
