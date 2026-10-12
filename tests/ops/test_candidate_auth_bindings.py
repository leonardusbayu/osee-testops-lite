"""Exercise exact binding checks without DB or private material."""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / 'scripts/generate-staff-queries.py'


class CandidateBindingModuleTests(unittest.TestCase):
    def check(self, *arguments):
        return subprocess.run([sys.executable, '-B', str(GENERATOR), *arguments, '--check'],
                              cwd=ROOT, capture_output=True, text=True, timeout=15)

    def test_auth_check_covers_actor_and_logout_bindings(self):
        result = self.check('--module', 'auth')
        self.assertEqual(result.returncode, 0, 'Exact auth SQL checker cannot validate actor-bearing transitions')

    def test_staff_default_still_checks_its_original_bindings(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, 'Default staff binding contract regressed')

    def test_selected_intake_binding_module_is_reviewable(self):
        result = self.check('--module', 'intake')
        self.assertEqual(result.returncode, 0, 'Selected intake SQL cannot be checked exactly')

    def test_enrolled_session_binding_module_is_reviewable(self):
        result = self.check('--module', 'sessions')
        self.assertEqual(result.returncode, 0, 'Enrolled assignment SQL cannot be checked exactly')

    def test_other_query_module_is_refused(self):
        result = self.check('--module', '../private')
        self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
