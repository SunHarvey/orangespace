#include "firewall_win.hpp"

#include "appcontainer_win.hpp"

#include <fwpmu.h>
#include <netfw.h>

#include <algorithm>
#include <cstring>

#pragma comment(lib, "fwpuclnt.lib")

namespace orangespace::sandbox {
namespace {
// {d3e22eec-1f74-4319-8e34-5e18e2d3ad6c}
constexpr GUID kProvider = {0xd3e22eec, 0x1f74, 0x4319, {0x8e, 0x34, 0x5e, 0x18, 0xe2, 0xd3, 0xad, 0x6c}};
// {eef940f6-10af-410f-bee3-6cfe5fd3eaa7}
constexpr GUID kSublayer = {0xeef940f6, 0x10af, 0x410f, {0xbe, 0xe3, 0x6c, 0xfe, 0x5f, 0xd3, 0xea, 0xa7}};
constexpr UINT32 kLoopback = 0x7f000001;  // 127.0.0.1 in host order, as WFP expects
constexpr UINT8 kTcp = 6;

enum class Match { all, non_tcp, wrong_address, wrong_port };
struct RuleSpec {
  const GUID* layer;
  Match match;
};

std::vector<RuleSpec> Rules(bool proxy) {
  std::vector<RuleSpec> r;
  if (proxy) {
    r = {{&FWPM_LAYER_ALE_AUTH_CONNECT_V4, Match::non_tcp},
         {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, Match::wrong_address},
         {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, Match::wrong_port}};
  } else {
    r = {{&FWPM_LAYER_ALE_AUTH_CONNECT_V4, Match::all}};
  }
  r.push_back({&FWPM_LAYER_ALE_AUTH_CONNECT_V6, Match::all});
  r.push_back({&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, Match::all});
  r.push_back({&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, Match::all});
  return r;
}

void Check(DWORD rc, const char* operation) {
  if (rc != ERROR_SUCCESS) throw Win32Error(operation, rc);
}

struct Transaction {
  HANDLE engine;
  bool open = false;
  explicit Transaction(HANDLE e) : engine(e) {
    Check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin");
    open = true;
  }
  void Commit() {
    Check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit");
    open = false;
  }
  ~Transaction() {
    if (open) FwpmTransactionAbort0(engine);
  }
};

bool IdentityCondition(const FWPM_FILTER_CONDITION0& c, const FirewallIdentity& who) {
  if (who.kind == FirewallIdentity::Kind::package_sid) {
    return c.fieldKey == FWPM_CONDITION_ALE_PACKAGE_ID && c.matchType == FWP_MATCH_EQUAL &&
           c.conditionValue.type == FWP_SID && c.conditionValue.sid &&
           GetLengthSid(c.conditionValue.sid) == who.bytes.size() &&
           std::memcmp(c.conditionValue.sid, who.bytes.data(), who.bytes.size()) == 0;
  }
  return c.fieldKey == FWPM_CONDITION_ALE_APP_ID && c.matchType == FWP_MATCH_EQUAL &&
         c.conditionValue.type == FWP_BYTE_BLOB_TYPE && c.conditionValue.byteBlob &&
         c.conditionValue.byteBlob->size == who.bytes.size() &&
         std::memcmp(c.conditionValue.byteBlob->data, who.bytes.data(), who.bytes.size()) == 0;
}

// Compares one installed filter with the expected rule for this identity/port.
bool FilterMatches(const FWPM_FILTER0& f, const RuleSpec& spec, const FirewallIdentity& who, std::uint16_t port) {
  if (f.layerKey != *spec.layer || f.subLayerKey != kSublayer || f.action.type != FWP_ACTION_BLOCK) return false;
  if (!f.providerKey || *f.providerKey != kProvider) return false;
  const UINT32 expected_conditions = spec.match == Match::all ? 1 : 2;
  if (f.numFilterConditions != expected_conditions) return false;
  bool has_package = false, has_extra = spec.match == Match::all;
  for (UINT32 i = 0; i < f.numFilterConditions; ++i) {
    const auto& c = f.filterCondition[i];
    if (c.fieldKey == FWPM_CONDITION_ALE_PACKAGE_ID || c.fieldKey == FWPM_CONDITION_ALE_APP_ID) {
      has_package = IdentityCondition(c, who);
    } else if (spec.match == Match::non_tcp && c.fieldKey == FWPM_CONDITION_IP_PROTOCOL) {
      has_extra = c.matchType == FWP_MATCH_NOT_EQUAL && c.conditionValue.type == FWP_UINT8 &&
                  c.conditionValue.uint8 == kTcp;
    } else if (spec.match == Match::wrong_address && c.fieldKey == FWPM_CONDITION_IP_REMOTE_ADDRESS) {
      has_extra = c.matchType == FWP_MATCH_NOT_EQUAL && c.conditionValue.type == FWP_UINT32 &&
                  c.conditionValue.uint32 == kLoopback;
    } else if (spec.match == Match::wrong_port && c.fieldKey == FWPM_CONDITION_IP_REMOTE_PORT) {
      has_extra = c.matchType == FWP_MATCH_NOT_EQUAL && c.conditionValue.type == FWP_UINT16 &&
                  c.conditionValue.uint16 == port;
    } else {
      return false;
    }
  }
  return has_package && has_extra;
}
}  // namespace

FirewallIdentity FirewallIdentity::Package(void* sid) {
  if (!sid || !IsValidSid(sid)) throw std::invalid_argument("package sid");
  FirewallIdentity id;
  id.kind = Kind::package_sid;
  const auto* b = static_cast<const BYTE*>(sid);
  id.bytes.assign(b, b + GetLengthSid(sid));
  return id;
}

FirewallIdentity FirewallIdentity::Executable(const std::wstring& image_path) {
  FWP_BYTE_BLOB* blob = nullptr;
  Check(FwpmGetAppIdFromFileName0(image_path.c_str(), &blob), "FwpmGetAppIdFromFileName");
  FirewallIdentity id;
  id.kind = Kind::app_id;
  id.bytes.assign(blob->data, blob->data + blob->size);
  FwpmFreeMemory0(reinterpret_cast<void**>(&blob));
  if (id.bytes.empty()) throw std::invalid_argument("empty AppId");
  return id;
}

SandboxFirewall::SandboxFirewall() {
  FWPM_SESSION0 session{};
  session.flags = FWPM_SESSION_FLAG_DYNAMIC;
  session.displayData.name = const_cast<wchar_t*>(L"OrangeSpace sandbox firewall");
  Check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine_), "FwpmEngineOpen");
  try {
    Transaction tx(engine_);
    FWPM_PROVIDER0 provider{};
    provider.providerKey = kProvider;
    provider.displayData.name = const_cast<wchar_t*>(L"OrangeSpace");
    Check(FwpmProviderAdd0(engine_, &provider, nullptr), "FwpmProviderAdd");
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = kSublayer;
    sublayer.providerKey = const_cast<GUID*>(&kProvider);
    sublayer.displayData.name = const_cast<wchar_t*>(L"OrangeSpace sandbox containment");
    sublayer.weight = 0xFFFF;
    Check(FwpmSubLayerAdd0(engine_, &sublayer, nullptr), "FwpmSubLayerAdd");
    tx.Commit();
  } catch (...) {
    FwpmEngineClose0(engine_);
    throw;
  }
}

SandboxFirewall::~SandboxFirewall() {
  // Dynamic session: closing the engine removes provider, sublayer and filters.
  if (engine_) FwpmEngineClose0(engine_);
}

void SandboxFirewall::Apply(const std::string& sandbox_id, const FirewallIdentity& who, std::uint16_t port) {
  if (!port) throw std::invalid_argument("proxy port");
  Install(sandbox_id, who, port);
}

void SandboxFirewall::Block(const std::string& sandbox_id, const FirewallIdentity& who) {
  Install(sandbox_id, who, 0);
}

void SandboxFirewall::Install(const std::string& sandbox_id, const FirewallIdentity& who, std::uint16_t port) {
  if (who.bytes.empty()) throw std::invalid_argument("firewall identity");
  std::lock_guard lock(mutex_);
  Installed next;
  next.who = who;
  next.port = port;
  FWP_BYTE_BLOB app_blob{static_cast<UINT32>(who.bytes.size()), const_cast<UINT8*>(who.bytes.data())};
  {
    Transaction tx(engine_);
    // Add the new rules before removing the old ones inside one transaction so
    // there is never a moment without containment.
    for (const auto& spec : Rules(port != 0)) {
      FWPM_FILTER_CONDITION0 conditions[2]{};
      conditions[0].matchType = FWP_MATCH_EQUAL;
      if (who.kind == FirewallIdentity::Kind::package_sid) {
        conditions[0].fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
        conditions[0].conditionValue.type = FWP_SID;
        conditions[0].conditionValue.sid = reinterpret_cast<SID*>(const_cast<BYTE*>(who.bytes.data()));
      } else {
        conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        conditions[0].conditionValue.byteBlob = &app_blob;
      }
      UINT32 count = 1;
      if (spec.match != Match::all) {
        auto& c = conditions[1];
        c.matchType = FWP_MATCH_NOT_EQUAL;
        if (spec.match == Match::non_tcp) {
          c.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
          c.conditionValue.type = FWP_UINT8;
          c.conditionValue.uint8 = kTcp;
        } else if (spec.match == Match::wrong_address) {
          c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
          c.conditionValue.type = FWP_UINT32;
          c.conditionValue.uint32 = kLoopback;
        } else {
          c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
          c.conditionValue.type = FWP_UINT16;
          c.conditionValue.uint16 = port;
        }
        count = 2;
      }
      FWPM_FILTER0 filter{};
      filter.displayData.name = const_cast<wchar_t*>(L"OrangeSpace sandbox block");
      filter.providerKey = const_cast<GUID*>(&kProvider);
      filter.layerKey = *spec.layer;
      filter.subLayerKey = kSublayer;
      filter.weight.type = FWP_UINT8;
      filter.weight.uint8 = 15;
      filter.action.type = FWP_ACTION_BLOCK;
      filter.numFilterConditions = count;
      filter.filterCondition = conditions;
      UINT64 id = 0;
      Check(FwpmFilterAdd0(engine_, &filter, nullptr, &id), "FwpmFilterAdd");
      next.filter_ids.push_back(id);
    }
    if (const auto it = sandboxes_.find(sandbox_id); it != sandboxes_.end()) {
      for (const auto id : it->second.filter_ids) Check(FwpmFilterDeleteById0(engine_, id), "FwpmFilterDeleteById");
    }
    tx.Commit();
  }
  sandboxes_[sandbox_id] = next;
  if (!VerifyLocked(next)) throw std::runtime_error("WFP readback does not match the requested sandbox policy");
}

void SandboxFirewall::Remove(const std::string& sandbox_id) {
  std::lock_guard lock(mutex_);
  RemoveLocked(sandbox_id);
}

void SandboxFirewall::RemoveLocked(const std::string& sandbox_id) {
  const auto it = sandboxes_.find(sandbox_id);
  if (it == sandboxes_.end()) return;
  Transaction tx(engine_);
  for (const auto id : it->second.filter_ids) {
    const DWORD rc = FwpmFilterDeleteById0(engine_, id);
    if (rc != ERROR_SUCCESS && rc != static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) Check(rc, "FwpmFilterDeleteById");
  }
  tx.Commit();
  sandboxes_.erase(it);
}

bool SandboxFirewall::Verify(const std::string& sandbox_id) {
  std::lock_guard lock(mutex_);
  const auto it = sandboxes_.find(sandbox_id);
  return it != sandboxes_.end() && VerifyLocked(it->second);
}

bool SandboxFirewall::VerifyLocked(const Installed& installed) {
  const auto specs = Rules(installed.port != 0);
  if (specs.size() != installed.filter_ids.size()) return false;
  for (std::size_t i = 0; i < specs.size(); ++i) {
    FWPM_FILTER0* f = nullptr;
    if (FwpmFilterGetById0(engine_, installed.filter_ids[i], &f) != ERROR_SUCCESS || !f) return false;
    const bool ok = FilterMatches(*f, specs[i], installed.who, installed.port);
    FwpmFreeMemory0(reinterpret_cast<void**>(&f));
    if (!ok) return false;
  }
  // No other filter of ours may name this identity (e.g. a stale permit).
  for (const GUID* layer : {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                            &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6}) {
    FWPM_FILTER_ENUM_TEMPLATE0 tmpl{};
    tmpl.providerKey = const_cast<GUID*>(&kProvider);
    tmpl.layerKey = *layer;
    tmpl.actionMask = 0xFFFFFFFF;
    HANDLE e = nullptr;
    if (FwpmFilterCreateEnumHandle0(engine_, &tmpl, &e) != ERROR_SUCCESS) return false;
    FWPM_FILTER0** entries = nullptr;
    UINT32 n = 0;
    bool ok = FwpmFilterEnum0(engine_, e, 4096, &entries, &n) == ERROR_SUCCESS;
    for (UINT32 k = 0; ok && k < n; ++k) {
      const auto& f = *entries[k];
      for (UINT32 c = 0; c < f.numFilterConditions; ++c) {
        const bool same_identity = IdentityCondition(f.filterCondition[c], installed.who);
        if (same_identity && std::find(installed.filter_ids.begin(), installed.filter_ids.end(), f.filterId) ==
                                installed.filter_ids.end())
          ok = false;
      }
    }
    if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
    FwpmFilterDestroyEnumHandle0(engine_, e);
    if (!ok) return false;
  }
  return true;
}

namespace {
struct NetIsoConfig {
  DWORD count = 0;
  PSID_AND_ATTRIBUTES entries = nullptr;
  ~NetIsoConfig() {
    if (!entries) return;
    for (DWORD i = 0; i < count; ++i) HeapFree(GetProcessHeap(), 0, entries[i].Sid);
    HeapFree(GetProcessHeap(), 0, entries);
  }
};
using GetConfig = decltype(&NetworkIsolationGetAppContainerConfig);
using SetConfig = decltype(&NetworkIsolationSetAppContainerConfig);
struct FirewallApi {
  HMODULE module = LoadLibraryExW(L"FirewallAPI.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  GetConfig get = nullptr;
  SetConfig set = nullptr;
  FirewallApi() {
    if (!module) throw Win32Error("LoadLibrary(FirewallAPI)", GetLastError());
    auto g = GetProcAddress(module, "NetworkIsolationGetAppContainerConfig");
    auto s = GetProcAddress(module, "NetworkIsolationSetAppContainerConfig");
    std::memcpy(&get, &g, sizeof(get));
    std::memcpy(&set, &s, sizeof(set));
    if (!get || !set) throw Win32Error("GetProcAddress(NetworkIsolation)", ERROR_PROC_NOT_FOUND);
  }
  ~FirewallApi() { FreeLibrary(module); }
};

void UpdateExemption(void* sid, bool add) {
  FirewallApi api;
  NetIsoConfig current;
  Check(api.get(&current.count, &current.entries), "NetworkIsolationGetAppContainerConfig");
  std::vector<SID_AND_ATTRIBUTES> next;
  bool present = false;
  for (DWORD i = 0; i < current.count; ++i) {
    if (EqualSid(current.entries[i].Sid, sid)) {
      present = true;
      if (!add) continue;
    }
    next.push_back(current.entries[i]);
  }
  if (add == present) return;
  if (add) next.push_back({sid, 0});
  Check(api.set(static_cast<DWORD>(next.size()), next.empty() ? nullptr : next.data()),
        "NetworkIsolationSetAppContainerConfig");
}
}  // namespace

void AddLoopbackExemption(void* sid) { UpdateExemption(sid, true); }
void RemoveLoopbackExemption(void* sid) { UpdateExemption(sid, false); }

}  // namespace orangespace::sandbox
