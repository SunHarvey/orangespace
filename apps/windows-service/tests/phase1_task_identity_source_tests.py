"""Source-contract checks only; NOT native API/task/ACL evidence."""
import pathlib
import unittest
P = pathlib.Path(__file__).parent
class SourceContracts(unittest.TestCase):
    def test_fixed_roles_and_no_secret_transport(self):
        s = (P / 'phase1_task_identity_observer.cpp').read_text()
        p = (P / 'phase1_task_identity_probe.cpp').read_text()
        for bad in ['CreateService', 'CreateProcess', 'CreateNamedPipe', 'AdjustTokenPrivileges',
                    'CreateRestrictedToken', 'SetTokenInformation', 'SetNamedSecurityInfo',
                    'TerminateProcess', 'TASK_CREATE_OR_UPDATE', 'TASK_LOGON_S4U']:
            self.assertNotIn(bad, s + p)
        self.assertIn('TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE', s)
        self.assertIn('TASK_LOGON_INTERACTIVE_TOKEN', s)
        self.assertIn('TASK_RUNLEVEL_LUA', s)
        self.assertIn('TASK_RUN_USE_SESSION_ID', s)
        self.assertIn('get_EnginePID', s)
        self.assertIn('GetProcessTimes', s)
        self.assertIn('TokenStatistics', s)
        self.assertIn('TokenIntegrityLevel', s)
        self.assertIn('TokenElevationType', s)
        self.assertIn('FILE_FLAG_OPEN_REPARSE_POINT', s)
        self.assertIn('CREATE_NEW', s)
        self.assertNotIn('GetCurrentProcessId', p)
        self.assertNotIn('CreateFile', p)
        self.assertIn('compilation_fixture', p)
    def test_no_promotion_and_no_existing_object_adoption(self):
        s = (P / 'phase1_task_identity_observer.cpp').read_text()
        self.assertIn('action_binding_unproved', s)
        self.assertIn('further_admission=false', s)
        self.assertIn('DeleteTask', s)
        self.assertIn('get_Xml', s)
        self.assertIn('get_InstanceGuid', s)
        self.assertIn('GetSecurityInfo', s)
        self.assertIn('GetFinalPathNameByHandleW', s)
        self.assertIn('INHERIT_ONLY_ACE', s)
        self.assertIn('SE_DACL_PROTECTED', s)
        self.assertIn('FILE_SHARE_READ', s)
        self.assertNotIn('GetExitCodeProcess', s)
    def test_unknown_registration_cannot_claim_absence(self):
        s = (P / 'phase1_task_identity_observer.cpp').read_text()
        self.assertNotIn('if (!created) return !run_attempted;', s)
        self.assertIn('if (!created) return false;', s)
        self.assertIn('verify_definition', s)
        self.assertIn('volatile const bool compilation_fixture', s)
    def test_held_objects_are_rechecked_through_readback(self):
        s = (P / 'phase1_task_identity_observer.cpp').read_text()
        self.assertIn('verify_held_continuity', s)
        self.assertGreaterEqual(s.count('verify_held_continuity();'), 2)
        self.assertIn('TokenPrivileges', s)
        self.assertIn('record-identity', s)

    def test_report_is_owned_before_any_task_creation(self):
        s = (P / 'phase1_task_identity_observer.cpp').read_text()
        self.assertLess(s.index('Record report(sink'), s.index('task.create(probe'))
        self.assertIn('Handle engine;', s)

if __name__ == '__main__': unittest.main()
