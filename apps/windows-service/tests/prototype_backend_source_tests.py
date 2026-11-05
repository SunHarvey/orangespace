"""Narrow factory / constructor ABI contract; not native execution."""
from pathlib import Path
r=Path(__file__).resolve().parents[3]
s=(r/'apps/windows-service/src/chain_windows.cpp').read_text()
h=(r/'apps/windows-service/include/orangespace/chain_windows.hpp').read_text()
assert 'make_prototype_platform_chain_backend()' in h, 'missing trusted prototype capability factory'
assert 'std::make_unique<WindowsBackend>(true,true)' in s
assert 'std::make_unique<WindowsBackend>();' in s
assert 'std::make_unique<WindowsBackend>(true);' in s
assert 'os_runtime_new_with_local_proxy_v1' in s
assert 'LocalChannel take_local_channel(' in s
assert 'os_runtime_take_local_channel_v1' in s
assert 'LocalChannelBuffer output;' in s
assert 'original_budget' in s and 'take_attempted' in s
print('prototype factory/private ABI source contract passed (not native)')
