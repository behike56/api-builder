"""Reproduce the local test/measurement evidence; never issue a ReleaseDecision."""
import hashlib
import io
import json
import platform
import re
import subprocess
import sys
import unittest
from pathlib import Path

from engine import SCHEMA
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def main():
    Draft202012Validator.check_schema(SCHEMA)
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    identifiers = list(test_ids(suite))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    (ROOT / 'test-results.txt').write_text(stream.getvalue())
    pilots = subprocess.run([sys.executable, str(ROOT / 'run_pilots.py')],
                            capture_output=True, text=True)
    pilot_results = json.loads((ROOT / 'pilot-results.json').read_text()) if pilots.returncode == 0 else None
    ct_ids = sorted(re.search(r'test_CT(\d{3})_', name).group(1)
                    for name in identifiers if re.search(r'test_CT(\d{3})_', name))
    sources = [ROOT / name for name in ('engine.py', 'application_audit.py', 'schema.json',
                                        'cli.py', 'run_pilots.py', 'verify_freeze.py')]
    sources += sorted((ROOT / 'tests').glob('*.py')) + sorted((ROOT / 'fixtures').glob('*.json'))
    sources += [ROOT.parent / 'api-security-design/05_Security_Design_IR_v0.2.md']
    report = {
        'reportVersion': '1', 'evaluationDate': '2026-11-07',
        'implementationSnapshot': '0.2.0-dev.20261107', 'python': platform.python_version(),
        'tests': {'run': result.testsRun, 'failures': len(result.failures),
                  'errors': len(result.errors), 'skipped': len(result.skipped),
                  'successful': result.wasSuccessful(), 'ids': identifiers},
        'ct': {'collected': len(ct_ids), 'ids': ['CT-' + x for x in ct_ids],
               'expectedIdsPresent': ct_ids == [f'{i:03}' for i in range(1, 27)]},
        'pilots': {'exitCode': pilots.returncode, 'summary': pilot_results['summary'] if pilot_results else None,
                   'stderr': pilots.stderr},
        'conformance': {key: 'partial; full normative requirements unavailable'
                        for key in ('C1', 'C2', 'C3', 'C4')},
        'freezeDecision': 'not-eligible',
        'blockers': [
            'Numbered normative C1-C4 requirements and independent acceptance oracle unavailable',
            'Full entity/relation cardinality and lifecycle contract incomplete',
            'Child claims, assumptions and defeaters not integrated into candidate assurance',
            'Evidence authenticity, independence and reviewer authority unverified',
            'Real code diff and Claim/Finding/Risk inventory completeness unverified',
            'ReleaseDecision issuance/authorization and real API/CI verification unimplemented'],
        'limits': 'Synthetic IR/CLI integration; no running API, CI authority or release permission tested',
        'inputDigestsSHA256': {str(p.relative_to(ROOT.parent)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sources}}
    output = ROOT / 'reports/freeze-audit-2026-11-07.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items()
                      if k in ('implementationSnapshot', 'freezeDecision', 'pilots')}, indent=2))
    print(f'Tests: {result.testsRun}, failures: {len(result.failures)}, errors: {len(result.errors)}')
    # Success means the experiment reproduced, never that the specification froze.
    return 0 if result.wasSuccessful() and pilots.returncode == 0 and report['ct']['expectedIdsPresent'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
