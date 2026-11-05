"""Local builder parsing tests, not protected Windows bootstrap tests."""
import importlib.util
import pathlib
import unittest
import sys
sys.dont_write_bytecode = True

HERE = pathlib.Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("identity_builder", HERE / "phase1_task_identity_build.py")

class BuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert SPEC and SPEC.loader
        cls.b = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.b)

    def fixture(self):
        return {"purpose": "compilation-fixture", "nonce": "a" * 32,
                "program_files": "C:\\Program Files", "sid": "S-1-5-21-1-2-3-1001",
                "observer_session": 0, "observer_luid": 100,
                "probe_session": 2, "probe_luid": 200,
                "root_volume": 1, "root_file_id": 2,
                "evidence_volume": 1, "evidence_file_id": 3}

    def test_exact_fixture_is_marked_not_native_approved(self):
        p = self.b.validate(self.fixture())
        self.assertTrue(p["compilation_fixture"])
        self.assertEqual(p["task_name"], "OrangeSpacePhase1TaskIdentity-" + "a" * 32)
        self.assertEqual(p["probe_session"], 2)

    def test_no_unknown_fields_or_arbitrary_commands(self):
        for k in ["command", "path", "mode", "selftest", "expected_exit", "trusted"]:
            with self.subTest(k=k):
                f = self.fixture(); f[k] = "arbitrary"
                with self.assertRaises(ValueError): self.b.validate(f)

    def test_reject_malformed_and_zero_identity(self):
        for key, value in [("nonce", "A" * 32), ("nonce", "a" * 31),
                           ("sid", "UserA"), ("sid", "S-1-5-18"),
                           ("sid", "S-1-5-21-1-2-3-1001 "),
                           ("program_files", "C:\\Users\\UserA"),
                           ("program_files", "C:\\Program Files\\.."),
                           ("probe_session", 0), ("probe_session", True),
                           ("probe_luid", 0), ("root_file_id", 0),
                           ("purpose", "selftest")]:
            with self.subTest(key=key, value=value):
                f = self.fixture(); f[key] = value
                with self.assertRaises(ValueError): self.b.validate(f)

    def test_distinct_root_objects(self):
        f = self.fixture(); f["evidence_file_id"] = 2
        with self.assertRaises(ValueError): self.b.validate(f)

    def test_independent_logon_inputs_may_equal_if_externally_observed(self):
        f = self.fixture(); f["probe_luid"] = f["observer_luid"]
        self.assertEqual(self.b.validate(f)["probe_luid"], 100)
        # Equality/difference authenticates neither input. Provenance is external.

    def test_probe_session_must_fit_RunEx_signed_LONG(self):
        f = self.fixture(); f["probe_session"] = 0x80000000
        with self.assertRaises(ValueError): self.b.validate(f)

    def test_external_input_is_format_not_authentication(self):
        f = self.fixture(); f["purpose"] = "external-os-input"
        self.assertFalse(self.b.validate(f)["compilation_fixture"])
        # Parsing a claimed SID is deliberately NOT proof that it is an actual OS SID.

    def test_generated_config_and_plan_pin_are_non_circular(self):
        p = self.b.validate(self.fixture())
        plan, header = self.b.configuration(p, "1" * 64)
        self.assertIn(b'compilation_fixture', plan)
        self.assertIn('compilation_fixture = true', header)
        self.assertIn('"' + self.b.sha(plan) + '"', header)
        self.assertIn('"' + '1' * 64 + '"', header)
        self.assertNotIn(b'observer_sha256', plan)
        self.assertNotIn('selftest', header.lower())
        self.assertNotEqual(self.b.configuration(p, "2" * 64)[0], plan)

if __name__ == "__main__": unittest.main()
