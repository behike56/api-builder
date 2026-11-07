"""Small, deterministic IR trace and declared-change audit for the pilot fixtures.

A complete path is a structural observation, not proof that the controls work.
"""
from collections import defaultdict, deque

STEPS = ('asset', 'threat', 'control', 'boundary', 'criterion', 'activity',
         'evidence', 'claim', 'assessment', 'candidate', 'policy')


def audit_traceability(doc, candidate_id=None):
    nodes = {n['id']: n for n in doc['nodes']}
    links = defaultdict(list)
    for r in doc['relations']:
        links[(r['source'], r['kind'])].append(r['target'])

    def out(source, kind):
        return links[(source, kind)]

    rows = []
    for req in (n for n in doc['nodes'] if n['kind'] == 'SecurityRequirement' and n['status'] != 'retired'):
        rid = req['id']
        assets = out(rid, 'protects')
        threats = [n['id'] for n in doc['nodes'] if n['kind'] == 'ThreatScenario'
                   and any(a in out(n['id'], 'threatens') for a in assets)]
        controls = [n['id'] for n in doc['nodes'] if n['kind'] == 'ControlApplication'
                    and rid in out(n['id'], 'addresses')
                    and any(t in out(n['id'], 'mitigates') for t in threats)]
        boundaries = [b for c in controls for b in out(c, 'enforcedAt')]
        criteria = [n['id'] for n in doc['nodes'] if n['kind'] == 'VerificationCriterion'
                    and (rid in out(n['id'], 'evaluates') or any(c in out(n['id'], 'evaluates') for c in controls))]
        activities = [n['id'] for n in doc['nodes'] if n['kind'] == 'VerificationActivity'
                      and any(v in out(n['id'], 'verifies') for v in criteria)]
        evidence = [n['id'] for n in doc['nodes'] if n['kind'] == 'Evidence'
                    and any(a in out(n['id'], 'generatedBy') for a in activities)]
        claims = [n['id'] for n in doc['nodes'] if n['kind'] == 'AssuranceClaim'
                  and rid in out(n['id'], 'claimsFor')
                  and any(e in out(arg, 'hasPremise') for arg in out(n['id'], 'supportedByArgument') for e in evidence)]
        assessments = [n['id'] for n in doc['nodes'] if n['kind'] == 'AssuranceAssessment'
                       and any(c in out(n['id'], 'assessesClaim') for c in claims)]
        candidates = [n['id'] for n in doc['nodes'] if n['kind'] == 'ReleaseCandidate'
                      and (candidate_id is None or n['id'] == candidate_id)
                      and any(c in out(n['id'], 'requiresClaim') for c in claims)]
        policies = [p for candidate in candidates for p in out(candidate, 'usesReleasePolicy')]
        stages = dict(zip(STEPS, (assets, threats, controls, boundaries, criteria, activities,
                                  evidence, claims, assessments, candidates, policies)))
        rows.append({'requirement': rid, 'complete': all(stages.values()),
                     'missing': [k for k, v in stages.items() if not v], 'paths': stages})
    return {'requirements': len(rows), 'complete': sum(r['complete'] for r in rows), 'rows': rows}


def affected_by_changes(doc, changed_ids):
    """Reverse typed dependencies, plus Evidence.dependencyRefs; unknown IDs remain visible."""
    nodes = {n['id']: n for n in doc['nodes']}
    reverse = defaultdict(set)
    for r in doc['relations']:
        if r['kind'] in ('protects', 'threatens', 'addresses', 'mitigates', 'enforcedAt',
                         'evaluates', 'verifies', 'generatedBy', 'hasPremise',
                         'supportedByArgument', 'claimsFor', 'requiresClaim'):
            reverse[r['target']].add(r['source'])
        # A changed control also affects criteria written against its requirement.
        # This is a conservative impact candidate, never automatic evidence reuse.
        if r['kind'] == 'addresses':
            reverse[r['source']].add(r['target'])
    for n in doc['nodes']:
        if n['kind'] == 'Evidence':
            for dependency in n['attributes'].get('dependencyRefs', []):
                reverse[dependency].add(n['id'])
    seen = set(changed_ids)
    queue = deque(changed_ids)
    while queue:
        for dependent in reverse[queue.popleft()]:
            if dependent not in seen:
                seen.add(dependent)
                queue.append(dependent)
    return {'changed': sorted(changed_ids), 'unknown': sorted(set(changed_ids) - set(nodes) -
            {d for n in doc['nodes'] for d in n['attributes'].get('dependencyRefs', [])}),
            'affected': sorted(seen),
            'evidence': sorted(x for x in seen if nodes.get(x, {}).get('kind') == 'Evidence'),
            'claims': sorted(x for x in seen if nodes.get(x, {}).get('kind') == 'AssuranceClaim')}
