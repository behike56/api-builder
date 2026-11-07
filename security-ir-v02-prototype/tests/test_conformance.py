"""CT-001..CT-026 are direct translations of the proposed conformance cases.

A passing test proves only this prototype meets its executable assertion;
it is NOT a third-party security certification.
"""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from engine import (FourValue, validate_schema, validate_graph, evaluate_argument,
                    count_distinct_evidence, evaluate_applicability, assess_claim,
                    evaluate_release_gate)

BASE = json.loads((ROOT/'fixtures/order_cancel_valid.json').read_text())
CATALOGS = json.loads((ROOT/'fixtures/catalogs.json').read_text())

def codes(doc, catalogs=CATALOGS):
    return {x.code for x in validate_graph(doc, catalogs=catalogs)}

def state(x): return FourValue.from_status(x)

def check_evidence(rev='A', scopes=('user','admin'), environment='staging'):
    return {'subject':'cancelOrder', 'revision':rev, 'environment':environment,
            'scope':list(scopes),'artifactRef':'ci://run/123',
            'producerRef':'security-tests','dependencyRefs':['policy-1']}

def target(rev='A', scopes=('user','admin'), environment='staging'):
    return {'subject':'cancelOrder','revision':rev,'environment':environment,
            'requiredScope':list(scopes)}

class ConformanceTests(unittest.TestCase):
    def test_CT001_valid_minimal_ir(self):
        self.assertEqual(codes(copy.deepcopy(BASE)),set())

    def test_CT002_duplicate_node(self):
        doc=copy.deepcopy(BASE);doc['nodes'].append(copy.deepcopy(doc['nodes'][0]));self.assertIn('duplicate-node-id',codes(doc))

    def test_CT003_dangling_reference(self):
        doc=copy.deepcopy(BASE);doc['relations'][0]['target']='MISSING';self.assertIn('dangling-reference',codes(doc))

    def test_CT004_invalid_relation_target(self):
        doc=copy.deepcopy(BASE);doc['relations'][0]['target']='CMP-001';self.assertIn('invalid-relation-target',codes(doc))

    def test_CT005_claim_cycle(self):
        doc=copy.deepcopy(BASE)
        for claim in ('CLAIM-A','CLAIM-B','CLAIM-C'):
            doc['nodes'].append({'id':claim,'kind':'AssuranceClaim','status':'draft','attributes':{'statement':claim,'scope':['cancelOrder']}})
            doc['nodes'].append({'id':'ARG-'+claim,'kind':'AssuranceArgument','status':'draft','attributes':{'operator':'allOf','rationale':'test'}})
            doc['relations'].append({'id':'R-P-'+claim,'kind':'supportedByArgument','source':claim,'target':'ARG-'+claim})
        for a,b in (('A','B'),('B','C'),('C','A')):
            doc['relations'].append({'id':'R-D-'+a,'kind':'hasPremise','source':'ARG-CLAIM-'+a,'target':'CLAIM-'+b})
        self.assertIn('claim-cycle-detected',codes(doc))

    def test_CT006_unavailable_catalog(self):
        doc=copy.deepcopy(BASE)
        self.assertIn('external-reference-unresolved',codes(doc, catalogs={}))
        self.assertIn('external-reference-not-found',codes(doc, catalogs={'security-controls@0.1.0':[], 'security-patterns@0.1.0':[]}))

    def test_CT007_required_field_missing(self):
        doc=copy.deepcopy(BASE);del doc['nodes'][1]['attributes']['statement']
        self.assertIn('schema-validation-failed',codes(doc))

    def test_CT008_all_supported(self):
        self.assertEqual(evaluate_argument('allOf',[state('supported'),state('supported')]).status,'supported')

    def test_CT009_all_with_unknown(self):
        self.assertEqual(evaluate_argument('allOf',[state('supported'),state('undetermined')]).status,'undetermined')

    def test_CT010_all_refuted(self):
        self.assertEqual(evaluate_argument('allOf',[state('supported'),state('refuted')]).status,'refuted')

    def test_CT011_any_supported_and_refuted(self):
        self.assertEqual(evaluate_argument('anyOf',[state('supported'),state('refuted')]).status,'supported')

    def test_CT012_any_all_refuted(self):
        self.assertEqual(evaluate_argument('anyOf',[state('refuted'),state('refuted')]).status,'refuted')

    def test_CT013_conflicting_all(self):
        self.assertEqual(evaluate_argument('allOf',[state('supported'),state('conflicted')]).status,'conflicted')

    def test_CT014_at_least(self):
        self.assertEqual(evaluate_argument('atLeast',[state('supported'),state('supported'),state('undetermined')],2).status,'supported')

    def test_CT015_bad_threshold(self):
        with self.assertRaisesRegex(ValueError,'invalid-threshold'):
            evaluate_argument('atLeast',[state('supported')]*3,4)

    def test_CT016_duplicate_evidence_not_independent(self):
        self.assertEqual(count_distinct_evidence(['EVD-1','EVD-1']),1)
        self.assertLess(count_distinct_evidence(['EVD-1','EVD-1']),2)

    def test_CT017_matching_evidence(self):
        self.assertEqual(evaluate_applicability(check_evidence(),target())['status'],'applicable')

    def test_CT018_policy_change(self):
        self.assertEqual(evaluate_applicability(check_evidence(),target('B'),changed_dependencies={'policy-1'})['status'],'needs-review')

    def test_CT019_insufficient_coverage(self):
        ev=check_evidence(scopes=('user',))
        self.assertEqual(evaluate_applicability(ev,target())['status'],'not-applicable')
        a=assess_claim(state('supported'),validity=['applicable'],required_scope={'user','admin'},covered_scope={'user'})
        self.assertNotEqual(a['status'],'supported')

    def test_CT020_unverified_assumption(self):
        self.assertEqual(assess_claim(state('supported'),validity=['applicable'],assumptions=['unverified'])['status'],'review-required')

    def test_CT021_critical_defeater(self):
        self.assertEqual(assess_claim(state('supported'),validity=['applicable'],defeaters=['open-critical'])['status'],'review-required')

    def test_CT022_all_release_checks_pass(self):
        checks={k:'pass' for k in ('claims','evidence','findings','risks','freshness')}
        self.assertEqual(evaluate_release_gate(checks),'ready')

    def test_CT023_release_blocking_finding(self):
        checks={k:'pass' for k in ('claims','evidence','findings','risks','freshness')};checks['findings']='fail'
        self.assertEqual(evaluate_release_gate(checks),'blocked')

    def test_CT024_risk_approval_pending(self):
        checks={k:'pass' for k in ('claims','evidence','findings','risks','freshness')};checks['risks']='review'
        self.assertEqual(evaluate_release_gate(checks),'review-required')

    def test_CT025_missing_policy_check(self):
        checks={k:'pass' for k in ('claims','evidence','findings','risks')}
        self.assertEqual(evaluate_release_gate(checks),'unknown')

    def test_CT026_blocking_and_unknown(self):
        checks={'claims':'pass','evidence':'unknown','findings':'fail','risks':'pass','freshness':'pass'}
        self.assertEqual(evaluate_release_gate(checks),'blocked')

    def test_property_no_evidence_does_not_support_claim(self):
        self.assertEqual(assess_claim(state('supported'), validity=[], reviewed=True)['status'], 'indeterminate')

    def test_property_unreviewed_argument_is_not_supported(self):
        self.assertEqual(assess_claim(state('supported'), validity=['applicable'])['status'], 'review-required')

    def test_property_approved_claim_requires_one_argument(self):
        doc=copy.deepcopy(BASE)
        doc['nodes'].append({'id':'CLAIM-X','kind':'AssuranceClaim','status':'approved',
                             'attributes':{'statement':'something','scope':['cancelOrder']}})
        self.assertIn('invalid-claim-argument-cardinality',codes(doc))

    def test_property_no_catalog_not_structural_pass(self):
        from engine import conformance_report
        self.assertEqual(conformance_report(copy.deepcopy(BASE),catalogs={})['conclusion'], 'indeterminate')

    def test_property_permutation_invariance(self):
        import itertools
        vals=[state('supported'),state('conflicted'),state('undetermined')]
        for op in ('allOf','anyOf'):
            expected=evaluate_argument(op,vals)
            for seq in itertools.permutations(vals):
                self.assertEqual(evaluate_argument(op,list(seq)),expected)

    def test_property_missing_mandatory_never_ready(self):
        for missing in ('claims','evidence','findings','risks','freshness'):
            checks={k:'pass' for k in ('claims','evidence','findings','risks','freshness') if k!=missing}
            self.assertNotEqual(evaluate_release_gate(checks),'ready')

    def test_property_unknown_does_not_override_blocker(self):
        self.assertEqual(evaluate_release_gate({'findings':'fail'}),'blocked')

if __name__=='__main__':
    unittest.main()
