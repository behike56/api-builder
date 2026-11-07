"""Public gate regression: false-ready cases found during the freeze audit."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from engine import evaluate_release_candidate
from run_pilots import CATALOGS, EVIDENCE_REGISTRY, PILOTS


def node(doc, identifier):
    return next(n for n in doc['nodes'] if n['id'] == identifier)


def load(name='pilot_multistage_approval.json'):
    return json.loads((ROOT / 'fixtures' / name).read_text())


def gate(doc, registry=EVIDENCE_REGISTRY):
    return evaluate_release_candidate(doc, 'RC-001', catalogs=CATALOGS,
                                      evidence_registry=registry)


class GateSafetyTests(unittest.TestCase):
    def test_duplicate_evidence_cannot_satisfy_at_least_two(self):
        doc = load()
        node(doc, 'ARG-001')['attributes'].update(operator='atLeast', threshold=2)
        edge = copy.deepcopy(next(r for r in doc['relations']
                                  if r['source'] == 'ARG-001' and r['kind'] == 'hasPremise'))
        edge['id'] = 'DUPLICATE-VOTE'
        doc['relations'].append(edge)
        self.assertEqual(gate(doc)['decision'], 'unknown')

    def test_repeated_link_does_not_change_all_of_result(self):
        doc = load()
        edge = copy.deepcopy(next(r for r in doc['relations']
                                  if r['source'] == 'ARG-001' and r['kind'] == 'hasPremise'))
        edge['id'] = 'DUPLICATE-LINK'
        doc['relations'].append(edge)
        self.assertEqual(gate(doc)['decision'], 'ready')

    def test_declared_ir_changes_invalidate_only_affected_stage(self):
        for changed in ('SR-004', 'CA-002', 'CMP-002', 'VC-002'):
            with self.subTest(changed=changed):
                doc = load()
                node(doc, 'RC-001')['attributes']['changedDependencies'] = [changed]
                result = gate(doc)
                self.assertEqual(result['decision'], 'review-required')
                self.assertEqual(result['basis']['changeImpact']['evidence'], ['EVD-002'])
                self.assertIn('EVD-002: evidence-reassessment-required', result['details']['evidence'])

    def test_unknown_declared_change_prevents_ready(self):
        doc = load()
        node(doc, 'RC-001')['attributes']['changedDependencies'] = ['unknown-policy']
        self.assertEqual(gate(doc)['decision'], 'unknown')

    def test_other_candidate_cannot_cover_missing_required_claim(self):
        doc = load()
        candidate = copy.deepcopy(node(doc, 'RC-001'))
        candidate['id'] = 'RC-OTHER'
        doc['nodes'].append(candidate)
        next(r for r in doc['relations'] if r['kind'] == 'requiresClaim'
             and r['target'] == 'CLAIM-002')['source'] = 'RC-OTHER'
        doc['relations'].append({'id': 'OTHER-POLICY', 'kind': 'usesReleasePolicy',
                                 'source': 'RC-OTHER', 'target': 'RP-001'})
        self.assertEqual(gate(doc)['decision'], 'unknown')

    def test_registry_binds_environment_scope_and_dependencies(self):
        for field, value in [('environment', 'production'), ('scope', ['user']),
                             ('dependencyRefs', ['different-policy'])]:
            with self.subTest(field=field):
                registry = copy.deepcopy(EVIDENCE_REGISTRY)
                registry['multistage-approval-api']['EVD-001'][field] = value
                result = gate(load(), registry)
                self.assertEqual(result['decision'], 'review-required')
                self.assertIn('EVD-001: registry-record-mismatch', result['details']['evidence'])

    def test_unapproved_or_retired_evidence_requires_review(self):
        for status in ('draft', 'reviewed', 'retired'):
            with self.subTest(status=status):
                doc = load()
                node(doc, 'EVD-001')['status'] = status
                self.assertEqual(gate(doc)['decision'], 'review-required')

    def test_risk_approver_string_does_not_override_unapproved_record(self):
        doc = load()
        node(doc, 'RISK-001')['status'] = 'draft'
        self.assertEqual(gate(doc)['decision'], 'review-required')

    def test_critical_finding_still_blocks_with_unknown_change(self):
        doc = load()
        node(doc, 'RC-001')['attributes']['changedDependencies'] = ['unknown-policy']
        node(doc, 'F-001')['attributes'].update(severity='critical', disposition='open')
        self.assertEqual(gate(doc)['decision'], 'blocked')

    def test_three_pilots_detect_ir_change_without_mutating_observation(self):
        for filename in PILOTS:
            with self.subTest(filename=filename):
                doc = load(filename)
                node(doc, 'RC-001')['attributes']['changedDependencies'] = ['SR-003']
                original = copy.deepcopy(doc)
                self.assertEqual(gate(doc)['decision'], 'review-required')
                self.assertEqual(doc, original)

    def temporal(self, observed='2026-11-06T12:00:00+09:00'):
        doc = load('pilot_order_cancel.json')
        node(doc, 'RP-001')['attributes']['maxEvidenceAgeSeconds'] = 86400
        node(doc, 'RC-001')['attributes']['evaluatedAt'] = '2026-11-07T12:00:00+09:00'
        node(doc, 'EVD-001')['attributes']['observedAt'] = observed
        registry = copy.deepcopy(EVIDENCE_REGISTRY)
        registry['order-cancel-api']['EVD-001']['observedAt'] = observed
        return doc, registry

    def test_evidence_exact_age_boundary_is_applicable(self):
        doc, registry = self.temporal()
        self.assertEqual(gate(doc, registry)['decision'], 'ready')

    def test_expired_or_future_evidence_requires_review(self):
        for observed in ('2026-11-06T11:59:59+09:00', '2026-11-07T12:00:01+09:00'):
            with self.subTest(observed=observed):
                doc, registry = self.temporal(observed)
                result = gate(doc, registry)
                self.assertEqual(result['decision'], 'review-required')
                self.assertEqual(result['checks']['freshness'], 'review')

    def test_missing_clock_or_observation_is_unknown_when_age_required(self):
        for identifier, field in [('RC-001', 'evaluatedAt'), ('EVD-001', 'observedAt')]:
            with self.subTest(field=field):
                doc, registry = self.temporal()
                del node(doc, identifier)['attributes'][field]
                self.assertNotEqual(gate(doc, registry)['decision'], 'ready')

    def test_invalid_age_and_timezone_are_unknown(self):
        for identifier, field, value in [('RP-001', 'maxEvidenceAgeSeconds', -1),
                                          ('RP-001', 'maxEvidenceAgeSeconds', True),
                                          ('RC-001', 'evaluatedAt', '2026-11-07T12:00:00'),
                                          ('EVD-001', 'observedAt', 'yesterday')]:
            with self.subTest(field=field, value=value):
                doc, registry = self.temporal()
                node(doc, identifier)['attributes'][field] = value
                self.assertEqual(gate(doc, registry)['decision'], 'unknown')


if __name__ == '__main__':
    unittest.main()
