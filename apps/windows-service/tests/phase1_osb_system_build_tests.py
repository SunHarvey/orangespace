import importlib.util,pathlib,unittest
P=pathlib.Path(__file__).parent
class BuildContract(unittest.TestCase):
 def test_build_rejects_unapproved_inputs_before_compiler(self):
  p=P/'phase1_osb_system_build.py'
  self.assertTrue(p.exists(),'missing provenance-producing isolated builder')
  spec=importlib.util.spec_from_file_location('builder',p)
  assert spec is not None and spec.loader is not None
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  for n,sid in [('x','S-1-5-21-1-2-3-1001'),('a'*24,'S-1-5-18'),('a'*24,'S-1-5-21-1-2-3-1001 & whoami')]:
   with self.assertRaises(ValueError):m.validate(n,sid)
  self.assertIsNone(m.validate('a'*24,'S-1-5-21-1-2-3-1001'))
if __name__=='__main__':unittest.main()
