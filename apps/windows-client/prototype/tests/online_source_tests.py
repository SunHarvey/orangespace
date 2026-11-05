from pathlib import Path
r=Path(__file__).resolve().parents[4]
s=(r/'apps/windows-service/prototype/service_win.cpp').read_text()
c=(r/'apps/windows-client/prototype/admission_client_win.cpp').read_text()
b=(r/'apps/windows-client/prototype/bootstrap_prototype_win.cc').read_text()
assert 'control.verify_live(*channel)' in s
assert 'package_network.verifyExactPolicy' in s
assert 'appendAfterVerifiedWfp' in s and 'removeOnlyOwned' in s
assert s.index('control.wait_channel') < s.index('root.create(runtime,session,channel->binding.sandbox)')
assert s.index('ValidPrivateReceipt(expected,acknowledged,6)') < s.index('private-committed-write')
assert c.index('st.private_owner=std::make_unique<PrivateOwner>()') < c.index('private_ack.phase=6')
assert c.index('ValidPrivateReceipt(expected,private_committed,2)') < c.index('if(!SetEvent(st.start.h))')
assert b.index('Admission::Acquire()') < b.index('loader.LoadInMainAssert')
assert 'new orangespace::prototype::OnlineApp' in b
print('online source ordering checks passed (not native acceptance)')
