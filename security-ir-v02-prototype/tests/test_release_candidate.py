"""Regression cases for IR-derived Release Gate decisions."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engine import evaluate_release_candidate, validate_graph

BASE = json.loads((ROOT / 'fixtures/release_candidate_valid.json').read_text())
CATALOGS = json.loads((ROOT / 'fixtures/catalogs.json').read_text())


def node(doc, node_id):
    return next(n for n in doc['nodes'] if n['id'] == node_id)


def gate(doc):
    return evaluate_release_candidate(doc, 'RC-001', catalogs=CATALOGS)


class ReleaseCandidateTests(unittest.TestCase):
    def test_ready_derived_from_linked_records(self):
        result = gate(copy.deepcopy(BASE))
        self.assertEqual(result['decision'], 'ready')
        self.assertEqual(set(result['checks'].values()), {'pass'})
        self.assertEqual(result['basis']['evidence'], ['EVD-001'])

    def test_old_evidence_requires_reassessment_without_rewriting_observation(self):
        doc = copy.deepcopy(BASE)
        node(doc, 'RC-001')['attributes']['artifactRevision'] = 'build-B'
        result = gate(doc)
        self.assertEqual(result['decision'], 'review-required')
        self.assertEqual(result['checks']['evidence'], 'review')
        self.assertEqual(result['checks']['freshness'], 'review')
        self.assertEqual(node(doc, 'EVD-001')['attributes']['result'], 'pass')

    def test_design_revision_change_requires_fresh_assessment(self):
        doc = copy.deepcopy(BASE)
        doc['design']['revision'] = 4
        self.assertEqual(gate(doc)['checks']['freshness'], 'review')

    def test_insufficient_assurance_blocks_or_remains_unknown(self):
        doc = copy.deepcopy(BASE)
        node(doc, 'EVD-001')['attributes']['result'] = 'fail'
        result = gate(doc)
        self.assertEqual(result['decision'], 'blocked')
        self.assertEqual(result['checks']['claims'], 'fail')

    def test_critical_open_finding_blocks(self):
        doc = copy.deepcopy(BASE)
        node(doc, 'F-001')['attributes'].update(severity='critical', disposition='open')
        self.assertEqual(gate(doc)['decision'], 'blocked')

    def test_unapproved_residual_risk_requires_review(self):
        doc = copy.deepcopy(BASE)
        del node(doc, 'RISK-001')['attributes']['approvedBy']
        self.assertEqual(gate(doc)['checks']['risks'], 'review')
        self.assertEqual(gate(doc)['decision'], 'review-required')

    def test_unresolved_policy_is_unknown(self):
        doc = copy.deepcopy(BASE)
        node(doc, 'RC-001')['attributes']['policyRef'] = 'RP-001@2.0.0'
        self.assertEqual(gate(doc)['reasons'], ['release-policy-unresolved'])
        self.assertEqual(gate(doc)['decision'], 'unknown')

    def test_missing_mandatory_policy_check_is_unknown(self):
        doc = copy.deepcopy(BASE)
        node(doc, 'RP-001')['attributes']['requiredChecks'].remove('freshness')
        self.assertEqual(gate(doc)['decision'], 'unknown')
        self.assertEqual(gate(doc)['reasons'], ['required-checks-missing-or-invalid'])

    def test_missing_validity_assessment_is_unknown(self):
        doc = copy.deepcopy(BASE)
        doc['nodes'] = [n for n in doc['nodes'] if n['id'] != 'EVA-001']
        doc['relations'] = [r for r in doc['relations'] if r['source'] != 'EVA-001']
        self.assertEqual(gate(doc)['checks']['evidence'], 'unknown')

    def test_unconfirmed_inventory_is_unknown(self):
        doc = copy.deepcopy(BASE)
        node(doc, 'RC-001')['attributes']['findingsComplete'] = False
        self.assertEqual(gate(doc)['decision'], 'unknown')

    def test_unresolved_external_catalog_is_unknown(self):
        result = evaluate_release_candidate(copy.deepcopy(BASE), 'RC-001')
        self.assertEqual(result['decision'], 'unknown')
        self.assertEqual(result['reasons'], ['external-catalog-unresolved'])

    def test_policy_and_candidate_relation_types_are_checked(self):
        doc = copy.deepcopy(BASE)
        relation = next(r for r in doc['relations'] if r['kind'] == 'usesReleasePolicy')
        relation['target'] = 'F-001'
        self.assertIn('invalid-relation-target', {f.code for f in validate_graph(doc)})


if __name__ == '__main__':
    unittest.main()
