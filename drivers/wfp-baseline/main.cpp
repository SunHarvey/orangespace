// This is a user-mode WFP policy utility, NOT the TCP/UDP redirection driver.
#include <windows.h>
#include <fwpmu.h>
#include <rpc.h>

#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr GUID kSublayer = {0x2068b93f, 0x5ba4, 0x4287,
                            {0xa9, 0x04, 0x31, 0x9a, 0x44, 0xcf, 0x11, 0x1b}};

void Check(DWORD code, const char* operation) {
    if (code != ERROR_SUCCESS) {
        throw std::runtime_error(std::string(operation) + " failed: " + std::to_string(code));
    }
}

struct Engine {
    HANDLE value = nullptr;
    Engine() { Check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &value), "open WFP"); }
    ~Engine() { if (value) FwpmEngineClose0(value); }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
};

struct Transaction {
    HANDLE engine;
    bool committed = false;
    explicit Transaction(HANDLE handle) : engine(handle) {
        Check(FwpmTransactionBegin0(engine, 0), "begin transaction");
    }
    ~Transaction() { if (!committed) FwpmTransactionAbort0(engine); }
    void Commit() { Check(FwpmTransactionCommit0(engine), "commit transaction"); committed = true; }
};

struct AppId {
    FWP_BYTE_BLOB* value = nullptr;
    explicit AppId(const wchar_t* path) {
        Check(FwpmGetAppIdFromFileName0(path, &value), "resolve application identity");
    }
    ~AppId() { if (value) FwpmFreeMemory0(reinterpret_cast<void**>(&value)); }
};

// Enumerate only to collect identifiers; never retain pointers after freeing a page.
std::vector<UINT64> OwnFilters(HANDLE engine) {
    HANDLE enumeration = nullptr;
    Check(FwpmFilterCreateEnumHandle0(engine, nullptr, &enumeration), "enumerate filters");
    std::vector<UINT64> identifiers;
    try {
        for (;;) {
            FWPM_FILTER0** entries = nullptr;
            UINT32 count = 0;
            Check(FwpmFilterEnum0(engine, enumeration, 128, &entries, &count), "read filters");
            for (UINT32 i = 0; i < count; ++i) {
                if (IsEqualGUID(entries[i]->subLayerKey, kSublayer)) {
                    identifiers.push_back(entries[i]->filterId);
                }
            }
            if (entries) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
            if (count == 0) break;
        }
    } catch (...) {
        FwpmFilterDestroyEnumHandle0(engine, enumeration);
        throw;
    }
    Check(FwpmFilterDestroyEnumHandle0(engine, enumeration), "close enumeration");
    return identifiers;
}

void AddBlock(HANDLE engine, const GUID& layer, FWP_BYTE_BLOB* application) {
    FWPM_FILTER_CONDITION0 condition{};
    condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condition.conditionValue.byteBlob = application;

    FWPM_FILTER0 filter{};
    Check(UuidCreate(&filter.filterKey), "create filter identifier");
    filter.displayData.name = const_cast<wchar_t*>(L"OrangeSpace browser deny baseline");
    filter.displayData.description = const_cast<wchar_t*>(L"Block-only foundation; does not authorize browsing");
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.layerKey = layer;
    filter.subLayerKey = kSublayer;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;
    filter.action.type = FWP_ACTION_BLOCK;
    Check(FwpmFilterAdd0(engine, &filter, nullptr, nullptr), "add block filter");
}

void Install(HANDLE engine, const wchar_t* path) {
    const std::filesystem::path executable(path);
    if (!executable.is_absolute() ||
        _wcsicmp(executable.filename().c_str(), L"OrangeSpace.BrowserHost.exe") != 0 ||
        !std::filesystem::is_regular_file(executable)) {
        throw std::runtime_error("expected an existing absolute OrangeSpace.BrowserHost.exe path");
    }
    AppId application(path);
    Transaction transaction(engine);
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = kSublayer;
    sublayer.displayData.name = const_cast<wchar_t*>(L"OrangeSpace deny baseline");
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.weight = 0xffff;
    // No provider is registered: this foundation must not depend on a fake service.
    const DWORD result = FwpmSubLayerAdd0(engine, &sublayer, nullptr);
    if (result != static_cast<DWORD>(FWP_E_ALREADY_EXISTS)) Check(result, "add sublayer");
    AddBlock(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V4, application.value);
    AddBlock(engine, FWPM_LAYER_ALE_AUTH_CONNECT_V6, application.value);
    AddBlock(engine, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, application.value);
    AddBlock(engine, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, application.value);
    transaction.Commit();
}

void Remove(HANDLE engine) {
    Transaction transaction(engine);
    for (const UINT64 identifier : OwnFilters(engine)) {
        Check(FwpmFilterDeleteById0(engine, identifier), "remove OrangeSpace filter");
    }
    const DWORD result = FwpmSubLayerDeleteByKey0(engine, &kSublayer);
    if (result != static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND)) Check(result, "remove OrangeSpace sublayer");
    transaction.Commit();
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc < 2) throw std::runtime_error("usage: orangespace-wfp-baseline status | install <BrowserHost.exe> | remove");
        const std::wstring command(argv[1]);
        if (!((command == L"status" && argc == 2) || (command == L"install" && argc == 3) ||
              (command == L"remove" && argc == 2))) {
            throw std::runtime_error("invalid command or argument count");
        }
        Engine engine;
        if (command == L"install") Install(engine.value, argv[2]);
        if (command == L"remove") Remove(engine.value);
        std::cout << "{\"schema_version\":1,\"block_filter_count\":" << OwnFilters(engine.value).size()
                  << ",\"browsing_allowed\":false,\"reason\":\"redirection_driver_and_dns_guard_not_implemented\"}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
