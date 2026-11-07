"""Reproducible synthetic pilot measurements. Writes pilot-results.json."""
import copy
import json
from pathlib import Path
from application_audit import audit_traceability, affected_by_changes
from engine import evaluate_release_candidate, validate_graph

ROOT = Path(__file__).resolve().parent
CATALOGS = json.loads((ROOT / 'fixtures/catalogs.json').read_text())
EVIDENCE_REGISTRY = json.loads((ROOT / 'fixtures/evidence_registry.json').read_text())
PILOTS = ('pilot_order_cancel.json', 'pilot_sensitive_read.json',
          'pilot_multistage_approval.json')


def node(doc, id):
    return next(n for n in doc['nodes'] if n['id'] == id)


def evaluate(doc):
    trace = audit_traceability(doc)
    gate = evaluate_release_candidate(doc, 'RC-001', catalogs=CATALOGS,
                                      evidence_registry=EVIDENCE_REGISTRY)
    graph = validate_graph(doc, profile='review', catalogs=CATALOGS)
    return {'trace': trace, 'gate': gate['decision'], 'graphFindings': [p.code for p in graph],
            'flagged': bool(graph) or trace['complete'] != trace['requirements'] or gate['decision'] != 'ready'}


def inject(doc, name):
    d = copy.deepcopy(doc)
    if name == 'missing_threat_control':
        d['relations'] = [r for r in d['relations'] if not (r['source'] == 'CA-001' and r['kind'] == 'mitigates')]
    elif name == 'missing_evidence_origin':
        d['relations'] = [r for r in d['relations'] if not (r['source'] == 'EVD-001' and r['kind'] == 'generatedBy')]
    elif name == 'missing_claim_requirement':
        d['relations'] = [r for r in d['relations'] if not (r['source'] == 'CLAIM-001' and r['kind'] == 'claimsFor')]
    elif name == 'stale_revision':
        node(d, 'EVD-001')['attributes']['revision'] = 'older-build'
    elif name == 'missing_validity_assessment':
        d['nodes'] = [n for n in d['nodes'] if n['id'] != 'EVA-001']
        d['relations'] = [r for r in d['relations'] if r['source'] != 'EVA-001']
    elif name == 'unverified_artifact_ref':
        # Same in-IR pass assertion could conceal a real-world failed test.
        node(d, 'EVD-001')['attributes']['artifactRef'] = 'ci://unverified-assertion'
    elif name == 'critical_open_finding':
        node(d, 'F-001')['attributes'].update(severity='critical', disposition='open')
    elif name == 'unapproved_residual_risk':
        node(d, 'RISK-001')['attributes'].pop('approvedBy', None)
    elif name == 'policy_version_mismatch':
        node(d, 'RC-001')['attributes']['policyRef'] = 'RP-001@missing'
    elif name == 'duplicate_evidence_vote':
        node(d, 'ARG-001')['attributes'].update(operator='atLeast', threshold=2)
        edge = copy.deepcopy(next(r for r in d['relations']
                                  if r['source'] == 'ARG-001' and r['kind'] == 'hasPremise'))
        edge['id'] = 'INJECT-DUPLICATE'
        d['relations'].append(edge)
    elif name == 'retired_evidence':
        node(d, 'EVD-001')['status'] = 'retired'
    elif name == 'unapproved_risk_record':
        node(d, 'RISK-001')['status'] = 'draft'
    elif name == 'unknown_declared_change':
        node(d, 'RC-001')['attributes']['changedDependencies'] = ['unknown-policy']
    elif name == 'registry_environment_mismatch':
        node(d, 'EVD-001')['attributes']['environment'] = 'production'
        node(d, 'RC-001')['attributes']['environmentRef'] = 'production'
    else:
        raise ValueError(name)
    return d


def main():
    expected = {'missing_threat_control': 'unknown', 'missing_evidence_origin': 'unknown',
                'missing_claim_requirement': 'unknown', 'stale_revision': 'review-required',
                'missing_validity_assessment': 'unknown', 'unverified_artifact_ref': 'review-required',
                'critical_open_finding': 'blocked', 'unapproved_residual_risk': 'review-required',
                'policy_version_mismatch': 'unknown', 'duplicate_evidence_vote': 'unknown',
                'retired_evidence': 'review-required', 'unapproved_risk_record': 'review-required',
                'unknown_declared_change': 'unknown', 'registry_environment_mismatch': 'review-required'}
    cases = []
    for filename in PILOTS:
        doc = json.loads((ROOT / 'fixtures' / filename).read_text())
        clean = evaluate(doc)
        injected = []
        for name, decision in expected.items():
            observed = evaluate(inject(doc, name))
            injected.append({'defect': name, 'detected': observed['flagged'],
                             'expectedGate': decision, 'gateMatchesExpected': observed['gate'] == decision,
                             'gate': observed['gate'], 'traceComplete': observed['trace']['complete'],
                             'graphFindings': observed['graphFindings']})
        stale = []
        for kind in ('revision','declared_dependency','ir_requirement','ir_boundary'):
            changed = copy.deepcopy(doc)
            if kind == 'revision':
                node(changed, 'RC-001')['attributes']['artifactRevision'] = 'next-build'
            elif kind == 'declared_dependency':
                node(changed, 'RC-001')['attributes']['changedDependencies'] = ['policy-1']
            else:
                node(changed, 'RC-001')['attributes']['changedDependencies'] = [
                    'SR-003' if kind == 'ir_requirement' else 'CMP-001']
            stale.append({'kind': kind, 'detected': evaluate(changed)['gate'] != 'ready',
                          'gate': evaluate(changed)['gate']})
        impact = affected_by_changes(doc, ['SR-003'])
        cases.append({'fixture': filename, 'requirements': clean['trace']['requirements'],
                      'traceComplete': clean['trace']['complete'], 'cleanFlagged': clean['flagged'],
                      'cleanGate': clean['gate'], 'defects': injected, 'staleness': stale,
                      'sampleImpact': impact})
    report = {'cases': cases, 'summary': {
        'requirements': sum(c['requirements'] for c in cases),
        'traceComplete': sum(c['traceComplete'] for c in cases),
        'injectedDefects': sum(len(c['defects']) for c in cases),
        'detectedDefects': sum(x['detected'] for c in cases for x in c['defects']),
        'cleanCasesFlagged': sum(c['cleanFlagged'] for c in cases),
        'cleanCases': len(cases),
        'stalenessScenarios': sum(len(c['staleness']) for c in cases),
        'detectedStaleness': sum(x['detected'] for c in cases for x in c['staleness']),
        'gateMatchesExpected': sum(x['gateMatchesExpected'] for c in cases for x in c['defects'])}}
    (ROOT / 'pilot-results.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(report['summary'], ensure_ascii=False, indent=2))
    # The measurement command itself fails if an expected result regresses.
    success = all(not c['cleanFlagged'] and c['cleanGate'] == 'ready'
                  and c['traceComplete'] == c['requirements']
                  and all(x['detected'] and x['gateMatchesExpected'] for x in c['defects'])
                  and all(x['detected'] for x in c['staleness']) for c in cases)
    return 0 if success else 1

if __name__ == '__main__':
    raise SystemExit(main())
