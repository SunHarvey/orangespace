"""Source wiring regressions only; never Windows IPC/network acceptance."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class PlatformEntryGlue(unittest.TestCase):
    def test_production_service_requires_platform_factory_without_legacy_fallback(self):
        source = (ROOT/'apps/windows-service/src/service_main.cpp').read_text()
        body = source.split('void run_service() {', 1)[1].split('void WINAPI service_main', 1)[0]
        self.assertIn('auto backend = make_platform_chain_backend();', body)
        self.assertNotIn('make_chain_backend()', body)

    def test_verified_owned_pipe_handler_routes_osp3_and_keeps_legacy_dispatch(self):
        source = (ROOT/'apps/windows-service/src/service_main.cpp').read_text()
        body = source.split('serve_owned_connection(connection.get(),expected,stop.get(),[this](auto bytes) {', 1)[1].split('});', 1)[0]
        self.assertIn("bytes.size() >= 4", body)
        for i, value in enumerate('OSP3'):
            self.assertIn(f"bytes[{i}] == '{value}'", body)
        self.assertIn('return dispatch_platform_chain(engine,expected,bytes);', body)
        self.assertIn('return dispatch_chain(engine,expected,bytes);', body)
        pipe = (ROOT/'apps/windows-service/src/pipe_server.cpp').read_text()
        self.assertLess(pipe.index('verified_peer(pipe, expected)'), pipe.index('owned = handler(bytes)'))
        self.assertIn('return owned.deliver(', pipe)
        self.assertIn('ack==6', pipe)

    def test_shared_sdk_and_private_native_store_fixture_link_central_sdk(self):
        service = (ROOT/'apps/windows-service/CMakeLists.txt').read_text()
        target = service.split('add_library(orangespace_node_session STATIC', 1)[1].split(')', 1)[0]
        self.assertIn('platform_session_win.cpp', target)
        client = (ROOT/'apps/windows-client/CMakeLists.txt').read_text()
        target = client.split('add_executable(orangespace-credential-store-native-tests', 1)[1].split(')', 1)[0]
        self.assertIn('platform_session_win.cpp', target)

    def test_private_ca_consumers_use_unified_runtime_without_policy_bypass(self):
        service = (ROOT/'apps/windows-service/CMakeLists.txt').read_text()
        sdk = service.split('target_link_libraries(orangespace_node_session PRIVATE', 1)[1].split(')', 1)[0]
        self.assertIn('${ORANGESPACE_RUNTIME_LIBRARY}', sdk)
        self.assertIn('dbghelp', sdk)
        self.assertNotIn('-ExecutionPolicy Bypass', service)
        client = (ROOT/'apps/windows-client/CMakeLists.txt').read_text()
        native = client.split('target_link_libraries(orangespace-credential-store-native-tests PRIVATE', 1)[1].split(')', 1)[0]
        self.assertIn('${ORANGESPACE_RUNTIME_LIBRARY}', native)


if __name__ == '__main__':
    unittest.main()
