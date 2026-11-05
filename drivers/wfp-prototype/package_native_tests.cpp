// Actual native rule construction/readback predicates. No BFE writes or sockets.
#ifdef _WIN32
#include "network_policy_win.cpp"
#else
#include "package_native_extracted.hpp"
#endif
#include <cassert>
#include <iostream>
using namespace orangespace::wfp_prototype;
namespace {
struct PackageSid {
  BYTE revision=1, count=8;
  SID_IDENTIFIER_AUTHORITY authority={{0,0,0,0,0,15}};
  DWORD sub[8]={2,11,22,33,44,55,66,77};
};
template<class F> void rejects(F f) {
  bool rejected=false; try { f(); } catch(const std::runtime_error&) { rejected=true; }
  assert(rejected);
}
bool matches(const FWPM_FILTER0& f,PSID package,FWP_BYTE_BLOB* image,
             unsigned protocol,unsigned address,unsigned port) {
  for(UINT32 i=0;i<f.numFilterConditions;++i) {
    const auto& c=f.filterCondition[i]; bool equal=false;
    if(eq(c.fieldKey,FWPM_CONDITION_ALE_PACKAGE_ID)) equal=!!EqualSid(c.conditionValue.sid,package);
    else if(eq(c.fieldKey,FWPM_CONDITION_ALE_APP_ID)) {
      FWP_CONDITION_VALUE0 v{}; v.type=FWP_BYTE_BLOB_TYPE; v.byteBlob=image;
      equal=sameValue(c.conditionValue,v);
    } else if(eq(c.fieldKey,FWPM_CONDITION_IP_PROTOCOL)) equal=protocol==c.conditionValue.uint8;
    else if(eq(c.fieldKey,FWPM_CONDITION_IP_REMOTE_ADDRESS)) equal=address==c.conditionValue.uint32;
    else if(eq(c.fieldKey,FWPM_CONDITION_IP_REMOTE_PORT)) equal=port==c.conditionValue.uint16;
    else assert(false);
    if(c.matchType==FWP_MATCH_EQUAL ? !equal : equal) return false;
  }
  return true;
}
}
int main() {
  check("test-success",0);
  PackageSid own, other; other.sub[7]++;
  validatePackageSid(&own);
  rejects([&]{validatePackageSid(nullptr);});
  auto bad=own; bad.authority.Value[5]=5; rejects([&]{validatePackageSid(&bad);});
  bad=own; bad.sub[0]=3; rejects([&]{validatePackageSid(&bad);});
  bad=own; bad.count=7; rejects([&]{validatePackageSid(&bad);});
  bad=own; bad.count=9; rejects([&]{validatePackageSid(&bad);});
  bad=own; bad.revision=2; rejects([&]{validatePackageSid(&bad);});
#ifdef _WIN32
  PackageNetworkPolicy invalid;
  rejects([&]{invalid.installOffline(nullptr);}); // Rejected before engine open.
  bad=own; bad.authority.Value[5]=5;
  rejects([&]{invalid.installOffline(&bad);});
#endif
  BYTE client[]={1,2,3}, sibling[]={4,5,6};
  FWP_BYTE_BLOB image{3,client}, differentImage{3,sibling};
  for(auto mode : {Mode::Offline,Mode::ProxyOnly}) {
    const auto rules=policyRules(mode,mode==Mode::Offline ? 0 : 3128);
    assert(rules.size()==(mode==Mode::Offline ? 4u : 6u));
    for(auto r:rules) {
      NativeRule package(r,nullptr,&own), path(r,&image);
      assert(!eq(package.filter.filterKey,path.filter.filterKey));
      assert(!eq(package.filter.subLayerKey,path.filter.subLayerKey));
      assert(package.filter.providerKey && !path.filter.providerKey);
      assert(eq(package.conditions[0].fieldKey,FWPM_CONDITION_ALE_PACKAGE_ID));
      assert(package.conditions[0].conditionValue.type==FWP_SID);
      assert(package.conditions[0].matchType==FWP_MATCH_EQUAL);
      for(UINT32 i=0;i<package.filter.numFilterConditions;++i)
        assert(!eq(package.conditions[i].fieldKey,FWPM_CONDITION_ALE_APP_ID));
      package.filter.filterId=42; path.filter.filterId=43;
      exact(package.filter,package.filter); exact(path.filter,path.filter);
      NativeRule changed(r,nullptr,&other); changed.filter.filterId=42;
      rejects([&]{exact(changed.filter,package.filter);});
      auto actual=package.filter; actual.flags^=FWPM_FILTER_FLAG_INDEXED;
      rejects([&]{exact(actual,package.filter);});
      actual=package.filter; actual.providerKey=nullptr; rejects([&]{exact(actual,package.filter);});
      actual=package.filter; actual.action.type=FWP_ACTION_PERMIT; rejects([&]{exact(actual,package.filter);});
      actual=package.filter; actual.subLayerKey=path.filter.subLayerKey; rejects([&]{exact(actual,package.filter);});
      UINT64 wrongWeight=1; actual=package.filter; actual.weight.uint64=&wrongWeight; rejects([&]{exact(actual,package.filter);});
      const auto saved=package.conditions[0].conditionValue.type;
      package.conditions[0].conditionValue.type=FWP_BYTE_BLOB_TYPE;
      rejects([&]{exact(package.filter,changed.filter);});
      package.conditions[0].conditionValue.type=saved;
    }
  }
  // Evaluate the actual generated native conditions, not a copied deny algorithm.
  for(auto* executable : {&image,&differentImage})
    for(unsigned protocol : {6u,17u,1u})
      for(unsigned address : {0x7f000001u,0x7f000002u,0x08080808u})
        for(unsigned port : {3128u,3129u,53u}) {
          bool denied=false,otherDenied=false;
          for(auto r:policyRules(Mode::ProxyOnly,3128)) {
            NativeRule package(r,nullptr,&own);
            if(r.layer==Layer::ConnectV4) {
              denied |= matches(package.filter,&own,executable,protocol,address,port);
              otherDenied |= matches(package.filter,&other,executable,protocol,address,port);
            }
          }
          assert(denied==!(protocol==6 && address==0x7f000001u && port==3128));
          assert(!otherDenied);
        }
  for(unsigned n=0;n<7;++n) for(unsigned m=0;m<7;++m) assert(!eq(key(n),packageKey(m)));
  std::cout << "PASS actual native rule/SID/exact-readback predicates; no kernel/socket acceptance\n";
}
