"""Source integration contracts; not native HWND/ACL/browser acceptance."""
from pathlib import Path
import unittest
from ui_test_slices import method
R=Path(__file__).resolve().parents[1]
class BrowserIntegration(unittest.TestCase):
 def test_browser_transport_prepares_before_authenticated_ack(self):
  s=(R/'src/service_client_win.cpp').read_text()
  self.assertIn('State exchange(const service_client::Grant&',s)
  self.assertIn('g.protocol()==3',s)
  self.assertIn('browser_wire_birth',s)
  self.assertLess(s.index('validate_browser_reply'),s.index('std::uint8_t ack = 6'))
 def test_owner_fenced_async_browser_and_independent_window(self):
  s=(R/'src/main_win.cpp').read_text()
  for token in ['poll_browser()', 'browser_worker_=std::thread', 'i->second==box->lease', 'GetProcessTimes(', 'QueryFullProcessImageNameW(', 'ProcessIdToSessionId(', 'bs::Command::close', 'station_.grant(', 'station_.restore()']:
   self.assertIn(token,s)
  self.assertNotIn('WM_COPYDATA',s)
  self.assertNotIn('SetParent(',s)
  self.assertNotIn('EnumWindows(',s)
  self.assertIn('browser_enabled(auth_.nodes()[index].node_id)',s)
  self.assertIn('browser_command_=bs::Command::close',s)
  self.assertIn('if(!tunnels_.empty())',s)
  self.assertIn('浏览暂不可用',s)
 def test_close_browser_before_helper(self):
  s=(R/'src/main_win.cpp').read_text()
  a=s.index('if(closing) {');z=s.index('out.stopped=stopping',a)
  self.assertLess(s[a:z].index('wait_browser_closed(*closing)'),s[a:z].index('sc::stop_tunnel'))
  helper=method(s,'  static bool close_browser_step(')
  self.assertLess(helper.index('bs::Command::status'),helper.index('bs::Command::close'))
  self.assertIn('state.phase==bs::Phase::closed && state.process_id==0',helper)
  self.assertIn('if(!lease.browser_close_requested)',helper)
  self.assertIn('lease.browser_close_requested=true;',helper)
  self.assertTrue(helper.rstrip().endswith('return false;\n  }'))
  wait=method(s,'  static void wait_browser_closed(')
  self.assertIn('if(close_browser_step(lease))return;',wait)
  self.assertIn('throw std::runtime_error("browser close not confirmed")',wait)
  # All three callers must retain close-before-stop/retire ordering; neither
  # an asynchronous close ACK nor an unknown/unsignalled root permits teardown.
  retry=method(s,'  void retry_stops()')
  self.assertLess(retry.index('if(!close_browser_step(lease)){++it;continue;}'),retry.index('sc::stop_tunnel'))
  cleanup=method(s,'  void cleanup_step()')
  self.assertIn('for(const auto& [local,lease]:tunnels_)',cleanup)
  self.assertIn('for(const auto& lease:pending_stops_)',cleanup)
  self.assertEqual(cleanup.count('if(lease->grant==grant && !close_browser_step(*lease))closed=false;'),2)
  guard='if(!closed || (browser_process_ && WaitForSingleObject(browser_process_,0)!=WAIT_OBJECT_0))return false;'
  self.assertLess(cleanup.index(guard),cleanup.index('return retirement_.run('))
  self.assertIn('[&]{sc::logout(*grant);},[&]{sc::retire(*grant);}',cleanup)
if __name__=='__main__': unittest.main()
