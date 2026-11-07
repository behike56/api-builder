"""End-to-end regression for the three synthetic API pilots and injected gaps."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from application_audit import audit_traceability, affected_by_changes
from engine import evaluate_release_candidate, validate_schema
from run_pilots import CATALOGS, EVIDENCE_REGISTRY, PILOTS, inject


def gate(doc, registry=EVIDENCE_REGISTRY):
    return evaluate_release_candidate(doc, 'RC-001', catalogs=CATALOGS,
                                      evidence_registry=registry)


class PilotTests(unittest.TestCase):
    def test_three_cases_trace_and_gate(self):
        for filename in PILOTS:
            with self.subTest(filename=filename):
                doc = json.loads((ROOT / 'fixtures' / filename).read_text())
                trace = audit_traceability(doc)
                self.assertEqual(trace['complete'], trace['requirements'])
                self.assertEqual(gate(doc)['decision'], 'ready')

    def test_missing_trace_links_are_visible(self):
        doc = json.loads((ROOT / 'fixtures/pilot_order_cancel.json').read_text())
        for defect, missing in [('missing_threat_control', 'control'),
                                ('missing_evidence_origin', 'evidence'),
                                ('missing_claim_requirement', 'claim')]:
            with self.subTest(defect=defect):
                row = audit_traceability(inject(doc, defect))['rows'][0]
                self.assertIn(missing, row['missing'])

    def test_change_impact_reaches_only_affected_approval_stage(self):
        doc = json.loads((ROOT / 'fixtures/pilot_multistage_approval.json').read_text())
        impact = affected_by_changes(doc, ['SR-004'])
        self.assertIn('EVD-002', impact['evidence'])
        self.assertIn('CLAIM-002', impact['claims'])
        self.assertNotIn('EVD-001', impact['evidence'])

    def test_missing_inventories_hold_gate(self):
        doc = json.loads((ROOT / 'fixtures/pilot_order_cancel.json').read_text())
        candidate = next(n for n in doc['nodes'] if n['id'] == 'RC-001')
        for key in ('claimsComplete', 'changedDependenciesComplete'):
            changed = copy.deepcopy(doc)
            next(n for n in changed['nodes'] if n['id'] == 'RC-001')['attributes'][key] = False
            result = gate(changed)
            self.assertEqual(result['decision'], 'unknown')

    def test_release_gate_requires_review_structure(self):
        doc = json.loads((ROOT / 'fixtures/pilot_order_cancel.json').read_text())
        doc['relations'] = [r for r in doc['relations'] if r['kind'] != 'enforcedAt']
        result = gate(doc)
        self.assertEqual(result['decision'], 'unknown')
        self.assertEqual(result['reasons'], ['graph-invalid'])

    def test_unapproved_validity_and_invalid_timestamp_do_not_pass(self):
        doc = json.loads((ROOT / 'fixtures/pilot_order_cancel.json').read_text())
        next(n for n in doc['nodes'] if n['id'] == 'EVA-001')['status'] = 'draft'
        self.assertEqual(gate(doc)['decision'], 'review-required')
        next(n for n in doc['nodes'] if n['id'] == 'AA-001')['attributes']['assessedAt'] = 'yesterday'
        self.assertTrue(validate_schema(doc))

    def test_registry_mismatch_and_missing_record_hold_gate(self):
        doc = json.loads((ROOT / 'fixtures/pilot_order_cancel.json').read_text())
        self.assertEqual(gate(inject(doc, 'unverified_artifact_ref'))['decision'], 'review-required')
        self.assertIn('EVD-001: registry-record-mismatch',
                      gate(inject(doc, 'unverified_artifact_ref'))['details']['evidence'])
        self.assertEqual(gate(doc, {})['decision'], 'unknown')

    def test_required_trace_gap_holds_gate(self):
        doc = json.loads((ROOT / 'fixtures/pilot_order_cancel.json').read_text())
        self.assertEqual(gate(inject(doc, 'missing_threat_control'))['decision'], 'unknown')

    def test_finding_risk_and_policy_affect_each_pilot(self):
        expected = {'critical_open_finding': 'blocked',
                    'unapproved_residual_risk': 'review-required',
                    'policy_version_mismatch': 'unknown'}
        for filename in PILOTS:
            doc = json.loads((ROOT / 'fixtures' / filename).read_text())
            for defect, decision in expected.items():
                with self.subTest(filename=filename, defect=defect):
                    self.assertEqual(gate(inject(doc, defect))['decision'], decision)


if __name__ == '__main__':
    unittest.main()
