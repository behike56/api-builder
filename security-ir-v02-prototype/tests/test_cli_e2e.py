"""Exercise JSON IO, candidate derivation, and process exit codes for every pilot."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from run_pilots import PILOTS, inject


class CliEndToEndTests(unittest.TestCase):
    def test_pilots_and_blockers_have_matching_cli_results_and_exit_codes(self):
        cases = [(None, 'ready', 0), ('critical_open_finding', 'blocked', 1),
                 ('unapproved_residual_risk', 'review-required', 2),
                 ('unknown_declared_change', 'unknown', 2)]
        with tempfile.TemporaryDirectory() as folder:
            for filename in PILOTS:
                base = json.loads((ROOT / 'fixtures' / filename).read_text())
                for defect, expected, code in cases:
                    with self.subTest(fixture=filename, defect=defect):
                        doc = inject(base, defect) if defect else base
                        source = Path(folder) / 'input.json'
                        output = Path(folder) / 'report.json'
                        source.write_text(json.dumps(doc))
                        result = subprocess.run([
                            sys.executable, str(ROOT / 'cli.py'), 'release-gate', str(source),
                            '--candidate', 'RC-001', '--catalogs', str(ROOT / 'fixtures/catalogs.json'),
                            '--evidence-registry', str(ROOT / 'fixtures/evidence_registry.json'),
                            '--output', str(output)], capture_output=True, text=True)
                        self.assertEqual(result.returncode, code, result.stderr)
                        self.assertEqual(json.loads(output.read_text())['decision'], expected)


if __name__ == '__main__':
    unittest.main()
