"""Policy/source-order regression only; NOT Windows native execution."""
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "service_win.cpp").read_text()

class StartupOrder(unittest.TestCase):
    def test_running_only_scm(self):
        body = SOURCE.split("bool scm_self(){", 1)[1].split("p::Reply native_mechanism_validated", 1)[0]
        self.assertNotIn("SERVICE_START_PENDING", body)
        self.assertIn("state.dwCurrentState==SERVICE_RUNNING", body)
        self.assertIn("state.dwProcessId==GetCurrentProcessId()", body)

    def test_actual_main_order(self):
        body = SOURCE.split("void WINAPI main_service", 1)[1]
        markers = ["network.installOffline(runtime.exe.wstring())",
                   "observation.publish({{session.id,session.peer}})",
                   "PrototypeControl control(", "control.start();status(SERVICE_RUNNING)",
                   "channel=control.wait_channel(200)", "need(bool(channel))",
                   "control.verify_live(*channel);need(session.same())",
                   "root.create(runtime,session)", "auto listener=pipe_for(session,root,true)",
                   "observation.publish({{session.id,session.peer},{0,pkgpeer}})",
                   "status(SERVICE_RUNNING)", "package_network.installOffline(root.package)",
                   "OwnedLoopbackExemption exemption(root.package)",
                   "control.verify_live(*channel)", "network.switchToProxyOnly(channel->port)",
                   "package_network.switchToProxyOnly(channel->port)",
                   "need(network.verifyExactPolicy(orangespace::wfp_prototype::Mode::ProxyOnly,channel->port).size()==6&&package_network.verifyExactPolicy(orangespace::wfp_prototype::Mode::ProxyOnly,channel->port).size()==6)",
                   "need(exemption.appendAfterVerifiedWfp().exact)",
                   "p::FreshRuleInspection inspections(",
                   "auto baseline=native_mechanism_validated(runtime,session,root,inspections)",
                   "control.verify_live(*channel);channel->budget.validate(",
                   "ResumeThread(root.thread.get())", "workers.emplace_back(", "admitted.insert("]
        # Search successive ranges, not the first occurrence of repeated RUNNING/
        # observation/control markers: online login precedes suspended Root creation.
        end = 0
        for marker in markers:
            end = body.index(marker, end) + len(marker)
        worker = body.split('workers.emplace_back([&,pipe=', 1)[1]
        self.assertLess(worker.index('reply=native_mechanism_validated('),
                        worker.index('stage="provisional-write"'))
        proof = SOURCE.split("p::Reply native_mechanism_validated", 1)[1].split("void admission_fence", 1)[0]
        for check in ['proof-job-containment', 'verify_job_members(r,s,root)',
                      'proof-runtime-pins', 'proof.rules_digest=inspections.snapshot()',
                      'proof-appcontainer-identity', 'WinLocalSystemSid)&&scm_self()']:
            self.assertIn(check, proof)
        self.assertIn("CREATE_SUSPENDED|", SOURCE.split("struct Root", 1)[1].split("bool contained", 1)[0])
        proof = SOURCE.split("p::Reply native_mechanism_validated", 1)[1].split("void status", 1)[0]
        self.assertIn("WinLocalSystemSid)&&scm_self()", proof)

if __name__ == "__main__":
    unittest.main()
