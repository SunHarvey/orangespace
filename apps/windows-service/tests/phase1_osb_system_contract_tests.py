"""Secondary source contract; NOT native Windows security evidence."""
import pathlib, unittest
P=pathlib.Path(__file__).parent
class Contract(unittest.TestCase):
 def test_real_winapi_adapter_and_worker(self):
  service=P/'phase1_osb_system_service.cpp'
  self.assertTrue(service.exists(), 'missing actual SCM WinAPI adapter')
  s=service.read_text()
  for term in ['StartServiceCtrlDispatcherW','RegisterServiceCtrlHandlerExW','WTSQueryUserToken','CreateProcessAsUserW','PROC_THREAD_ATTRIBUTE_JOB_LIST','IsProcessInJob','GetProcessTimes','ResumeThread','WaitForMultipleObjects','SetFileInformationByHandle','GetSecurityInfo','GetFinalPathNameByHandleW','FILE_SHARE_READ','FlushFileBuffers']:
   self.assertIn(term,s)
  for forbidden in ['LogonUser','NetUserAdd','LoadUserProfile','SetTokenInformation','AssignProcessToJobObject','CreateNamedPipe','OpenSCManager','CreateService','AdjustTokenPrivileges']:
   self.assertNotIn(forbidden,s)
  w=P/'phase1_osb_system_probe_worker.cpp'
  self.assertTrue(w.exists(),'missing fixed admission worker')
  for term in ['OpenProcessToken','TokenSessionId','TokenElevationType','IsProcessInJob']:
   self.assertIn(term,w.read_text())
 def test_api_failure_codes_distinct_from_policy_failures(self):
  h=(P/'phase1_osb_system_win.hpp').read_text()
  self.assertIn('inline void win(bool b)',h)
  self.assertIn('throw DWORD(ERROR_INVALID_DATA)',h)
 def test_receipt_carries_held_identity_and_external_binding(self):
  s=(P/'phase1_osb_system_service.cpp').read_text()
  for field in ['source_sid=','child_sid=','child_session=','job_member=','worker_volume=','worker_index_high=','plan_sha256=','worker_sha256=']:
   self.assertIn(field,s)
 def test_cleanup_checks_creator_job_handle_close(self):
  s=(P/'phase1_osb_system_service.cpp').read_text()
  self.assertIn('if(!CloseHandle(owned_job))',s)
  self.assertIn('cleanup_uncertain=true',s)
 def test_membership_is_proved_while_suspended_not_after_exit(self):
  s=(P/'phase1_osb_system_service.cpp').read_text()
  resume=s.split('bool resume_wait(){',1)[1].split('bool cleanup(){',1)[0]
  self.assertNotIn('IsProcessInJob',resume)
  self.assertIn('job_member,exit_code',resume)
if __name__=='__main__':unittest.main()
