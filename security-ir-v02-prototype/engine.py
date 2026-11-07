"""Security Design IR v0.2: deliberately limited conformance prototype.

All evaluations are deterministic; no assurance claim is automatically certified.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from collections import defaultdict
from pathlib import Path
from typing import Any
from datetime import datetime
import json
import hashlib

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent
SCHEMA = json.loads((ROOT / 'schema.json').read_text(encoding='utf-8'))

RELATIONS = {
    'protects': (('SecurityRequirement',), ('Asset',)),
    'threatens': (('ThreatScenario',), ('Asset',)),
    'addresses': (('ControlApplication',), ('SecurityRequirement',)),
    'mitigates': (('ControlApplication',), ('ThreatScenario',)),
    'justifies': (('DesignDecision',), ('ControlApplication',)),
    'realizes': (('PatternApplication',), ('ControlApplication',)),
    'enforcedAt': (('ControlApplication',), ('Component',)),
    'evaluates': (('VerificationCriterion',), ('SecurityRequirement', 'ControlApplication')),
    'supportedByArgument': (('AssuranceClaim',), ('AssuranceArgument',)),
    'hasPremise': (('AssuranceArgument',), ('AssuranceClaim', 'Evidence', 'Assumption')),
    'generatedBy': (('Evidence',), ('VerificationActivity',)),
    'verifies': (('VerificationActivity',), ('VerificationCriterion',)),
    'assessesEvidence': (('EvidenceValidityAssessment',), ('Evidence',)),
    'forClaim': (('EvidenceValidityAssessment',), ('AssuranceClaim',)),
    'assessesClaim': (('AssuranceAssessment',), ('AssuranceClaim',)),
    'claimsFor': (('AssuranceClaim',), ('SecurityRequirement',)),
    'considersAssessment': (('ReleaseDecision',), ('AssuranceAssessment',)),
    'considersRisk': (('ReleaseDecision',), ('ResidualRisk',)),
    'usesReleasePolicy': (('ReleaseCandidate',), ('ReleasePolicy',)),
    'requiresClaim': (('ReleaseCandidate',), ('AssuranceClaim',)),
    'tracksFinding': (('ReleaseCandidate',), ('Finding',)),
    'tracksRisk': (('ReleaseCandidate',), ('ResidualRisk',)),
}

@dataclass(frozen=True)
class Finding:
    code: str
    target: str
    detail: str
    severity: str = 'error'


def validate_schema(doc: dict) -> list[Finding]:
    findings = [Finding('schema-validation-failed', '/' + '/'.join(str(p) for p in e.absolute_path), e.message)
                for e in Draft202012Validator(SCHEMA, format_checker=Draft202012Validator.FORMAT_CHECKER).iter_errors(doc)]
    if findings:
        return findings
    timestamps = {'AssuranceAssessment': 'assessedAt', 'Evidence': 'observedAt',
                  'ReleaseCandidate': 'evaluatedAt'}
    for node in doc['nodes']:
        field = timestamps.get(node['kind'])
        if field and field in node['attributes']:
            value = node['attributes'][field]
            try:
                parsed = datetime.fromisoformat(value)
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    raise ValueError('timezone required')
            except (TypeError, ValueError):
                findings.append(Finding('invalid-assessment-timestamp', node['id'], f'{field}: {value}'))
    return findings


def validate_graph(doc: dict, *, profile: str = 'review', catalogs: dict | None = None) -> list[Finding]:
    if profile not in ('draft', 'review', 'release'):
        raise ValueError('invalid profile')
    problems = validate_schema(doc)
    if problems:
        return problems
    nodes = doc['nodes']; relations = doc['relations']
    findings: list[Finding] = []
    index: dict[str, dict] = {}
    for n in nodes:
        if n['id'] in index:
            findings.append(Finding('duplicate-node-id', n['id'], 'node id repeated'))
        index[n['id']] = n
    seen_rel = set()
    for e in relations:
        if e['id'] in seen_rel:
            findings.append(Finding('duplicate-relation-id', e['id'], 'relation id repeated'))
        seen_rel.add(e['id'])
        if e['source'] not in index or e['target'] not in index:
            findings.append(Finding('dangling-reference', e['id'], 'missing endpoint'))
            continue
        pairs = RELATIONS.get(e['kind'])
        if not pairs:
            findings.append(Finding('unknown-relation-type', e['id'], e['kind']))
            continue
        source_kind, target_kind = index[e['source']]['kind'], index[e['target']]['kind']
        if source_kind not in pairs[0]:
            findings.append(Finding('invalid-relation-source', e['id'], source_kind))
        if target_kind not in pairs[1]:
            findings.append(Finding('invalid-relation-target', e['id'], target_kind))
    if profile != 'draft':
        for n in nodes:
            if n['kind'] == 'SecurityRequirement' and n['status'] != 'retired':
                if not any(e['kind'] == 'protects' and e['source'] == n['id'] for e in relations):
                    findings.append(Finding('missing-protected-asset', n['id'], 'no protects relation'))
                if not any(e['kind'] == 'evaluates' and e['target'] == n['id'] for e in relations):
                    findings.append(Finding('missing-verification-criterion', n['id'], 'no verification criterion'))
            if n['kind'] == 'ControlApplication' and n['status'] == 'approved':
                if not any(e['kind'] == 'enforcedAt' and e['source'] == n['id'] for e in relations):
                    findings.append(Finding('missing-enforcement-point', n['id'], 'no enforcedAt relation'))
    findings.extend(validate_claim_cycles(index, relations))
    if profile != 'draft':
        for n in nodes:
            if n['status'] != 'approved':
                continue
            outgoing = [r for r in relations if r['source'] == n['id']]
            if n['kind'] == 'AssuranceClaim':
                arguments = [r for r in outgoing if r['kind'] == 'supportedByArgument']
                if len(arguments) != 1:
                    findings.append(Finding('invalid-claim-argument-cardinality', n['id'],
                                            f'expected one adopted argument, got {len(arguments)}'))
            if n['kind'] == 'AssuranceArgument':
                premises = [r for r in outgoing if r['kind'] == 'hasPremise']
                if not premises:
                    findings.append(Finding('missing-argument-premises', n['id'], 'no premises'))
    # v0.2 external catalog references are attributes, never local edges.
    for n in nodes:
        if n['kind'] not in ('PatternApplication', 'ControlApplication'):
            continue
        key = 'patternRef' if n['kind'] == 'PatternApplication' else 'controlRef'
        ref = n['attributes'].get(key, '')
        parts = ref.split(':', 1)
        if len(parts) != 2 or '@' not in parts[0] or not parts[1]:
            findings.append(Finding('unversioned-external-reference', n['id'], ref))
        elif catalogs is None or parts[0] not in catalogs:
            findings.append(Finding('external-reference-unresolved', n['id'], ref, 'warning'))
        elif parts[1] not in catalogs[parts[0]]:
            findings.append(Finding('external-reference-not-found', n['id'], ref))
    return findings


def validate_claim_cycles(nodes: dict[str, dict], edges: list[dict]) -> list[Finding]:
    # Claim -> Argument -> Claim represents semantic dependency.
    claim_arguments = defaultdict(list)
    premises = defaultdict(list)
    for r in edges:
        if r['kind'] == 'supportedByArgument':
            claim_arguments[r['source']].append(r['target'])
        if r['kind'] == 'hasPremise' and nodes.get(r['target'], {}).get('kind') == 'AssuranceClaim':
            premises[r['source']].append(r['target'])
    graph = {c: [sub for arg in args for sub in premises[arg]] for c, args in claim_arguments.items()}
    visiting, visited = set(), set()
    def dfs(current, path):
        if current in visiting:
            return path[path.index(current):] + [current]
        if current in visited:
            return None
        visiting.add(current)
        for child in graph.get(current, ()):
            cycle = dfs(child, path + [child])
            if cycle:
                return cycle
        visiting.remove(current); visited.add(current)
        return None
    for c in graph:
        found = dfs(c, [c])
        if found:
            return [Finding('claim-cycle-detected', c, ' -> '.join(found))]
    return []

@dataclass(frozen=True)
class FourValue:
    positive: bool = False
    negative: bool = False

    @property
    def status(self):
        return ('conflicted' if self.positive and self.negative else
                'supported' if self.positive else 'refuted' if self.negative else 'undetermined')

    @classmethod
    def from_status(cls, value: str):
        states = {'supported': (True, False), 'refuted': (False, True),
                  'conflicted': (True, True), 'undetermined': (False, False)}
        return cls(*states[value])


def evaluate_argument(op: str, premises: list[FourValue], threshold: int | None = None) -> FourValue:
    if not premises:
        raise ValueError('argument requires premises')
    m = len(premises)
    positives = sum(p.positive for p in premises)
    negatives = sum(p.negative for p in premises)
    if op == 'allOf':
        return FourValue(positives == m, negatives > 0)
    if op == 'anyOf':
        return FourValue(positives > 0, negatives == m)
    if op == 'atLeast':
        if type(threshold) is not int or not 1 <= threshold <= m:
            raise ValueError('invalid-threshold')
        return FourValue(positives >= threshold, negatives > m-threshold)
    raise ValueError('unknown operator')


def count_distinct_evidence(evidence_ids: list[str]) -> int:
    """Dedup by ID. Independent provenance is a separate review requirement."""
    return len(set(evidence_ids))


def evaluate_applicability(evidence: dict, target: dict, *, changed_dependencies: set[str] | None = None) -> dict:
    """A single evidence record's applicability, not completeness of a claim's evidence set."""
    reasons = []
    if not evidence.get('artifactRef') or not evidence.get('producerRef'):
        return {'status': 'unknown', 'reasons': ['unverifiable-provenance']}
    if evidence.get('subject') != target.get('subject'):
        return {'status': 'not-applicable', 'reasons': ['subject-mismatch']}
    if evidence.get('environment') != target.get('environment'):
        return {'status': 'needs-review', 'reasons': ['environment-differs']}
    required = set(target.get('requiredScope', []))
    actual = set(evidence.get('scope', []))
    if not (required <= actual):
        return {'status': 'not-applicable', 'reasons': ['insufficient-scope']}
    if evidence.get('revision') != target.get('revision'):
        reasons.append('revision-mismatch')
    if set(evidence.get('dependencyRefs', [])) & set(changed_dependencies or ()):
        reasons.append('dependency-changed')
    if reasons:
        return {'status': 'needs-review', 'reasons': reasons}
    return {'status': 'applicable', 'reasons': []}


def assess_claim(argument: FourValue, *, validity: list[str], assumptions: list[str] | None = None,
                 defeaters: list[str] | None = None, reviewed: bool = False,
                 required_scope: set[str] | None = None, covered_scope: set[str] | None = None) -> dict:
    """Conservative gate; evidence sufficiency remains a human-reviewed policy.

    Separate refutation from insufficient scope; no automatic certification.
    """
    assumptions = assumptions or []
    defeaters = defeaters or []
    if not validity:
        return {'status': 'indeterminate', 'reasonCodes': ['missing-evidence-validity']}
    if argument.status == 'refuted':
        return {'status': 'unsupported', 'reasonCodes': ['counterevidence-found']}
    if argument.status == 'conflicted':
        return {'status': 'review-required', 'reasonCodes': ['conflicting-support']}
    if required_scope is not None and not required_scope <= (covered_scope or set()):
        return {'status': 'indeterminate', 'reasonCodes': ['insufficient-coverage']}
    if 'not-applicable' in validity or 'unknown' in validity:
        return {'status': 'indeterminate', 'reasonCodes': ['invalid-or-unknown-evidence']}
    if 'needs-review' in validity:
        return {'status': 'review-required', 'reasonCodes': ['evidence-reassessment-required']}
    if 'invalidated' in assumptions:
        return {'status': 'review-required', 'reasonCodes': ['assumption-invalidated']}
    if 'unverified' in assumptions:
        return {'status': 'review-required', 'reasonCodes': ['assumption-unverified']}
    if 'open-critical' in defeaters:
        return {'status': 'review-required', 'reasonCodes': ['critical-defeater-open']}
    if argument.status == 'undetermined':
        return {'status': 'indeterminate', 'reasonCodes': ['argument-undetermined']}
    if not reviewed:
        return {'status': 'review-required', 'reasonCodes': ['argument-review-pending']}
    # Supported in this minimal evaluator means policy preconditions were met;
    # this does NOT certify completeness of the underlying threat model.
    return {'status': 'supported', 'reasonCodes': []}

REQUIRED_RELEASE_CHECKS = frozenset({'claims', 'evidence', 'findings', 'risks', 'freshness'})


def evaluate_release_gate(checks: dict[str, str], *, required_checks: frozenset[str] = REQUIRED_RELEASE_CHECKS):
    """Mandatory checks must come from a versioned policy, never just supplied results."""
    if not required_checks:
        raise ValueError('release policy cannot have zero checks')
    values = [checks.get(key, 'unknown') for key in required_checks]
    if any(v not in ('pass','fail','review','unknown') for v in values):
        raise ValueError('invalid check result')
    if 'fail' in values:
        return 'blocked'
    if 'review' in values:
        return 'review-required'
    if 'unknown' in values:
        return 'unknown'
    return 'ready'


def evaluate_release_candidate(doc: dict, candidate_id: str, *, catalogs: dict | None = None,
                               evidence_registry: dict | None = None) -> dict:
    """Derive gate checks from a candidate's linked IR records.

    Records and completeness declarations are input assertions, not authenticated facts.
    A missing or malformed policy can never produce a ready decision.
    """
    problems = validate_schema(doc)
    if problems:
        return {'candidateId': candidate_id, 'decision': 'unknown', 'checks': {},
                'reasons': ['schema-invalid'], 'structureFindings': [asdict(p) for p in problems]}
    nodes = {n['id']: n for n in doc['nodes']}
    candidate = nodes.get(candidate_id)
    if not candidate or candidate['kind'] != 'ReleaseCandidate':
        raise ValueError('unknown release candidate')
    relations = doc['relations']
    graph_results = validate_graph(doc, profile='review', catalogs=catalogs)
    graph_problems = [p for p in graph_results
                      if p.severity == 'error']
    if graph_problems:
        return {'candidateId': candidate_id, 'decision': 'unknown', 'checks': {},
                'reasons': ['graph-invalid'], 'structureFindings': [asdict(p) for p in graph_problems]}
    if any(p.code == 'external-reference-unresolved' for p in graph_results):
        return {'candidateId': candidate_id, 'decision': 'unknown', 'checks': {},
                'reasons': ['external-catalog-unresolved']}

    def targets(source: str, kind: str) -> list[str]:
        return [r['target'] for r in relations if r['source'] == source and r['kind'] == kind]

    attrs = candidate['attributes']
    ref = attrs['policyRef']
    policy_id, separator, version = ref.rpartition('@')
    policy_links = targets(candidate_id, 'usesReleasePolicy')
    policy = nodes.get(policy_id)
    if (not separator or not version or policy_links != [policy_id] or not policy
            or policy['kind'] != 'ReleasePolicy' or policy['status'] != 'approved'
            or policy['attributes']['version'] != version):
        return {'candidateId': candidate_id, 'policyRef': ref, 'decision': 'unknown',
                'checks': {}, 'reasons': ['release-policy-unresolved']}
    policy_attrs = policy['attributes']
    required = policy_attrs['requiredChecks']
    if (len(required) != len(set(required)) or set(required) != REQUIRED_RELEASE_CHECKS):
        return {'candidateId': candidate_id, 'policyRef': ref, 'decision': 'unknown',
                'checks': {}, 'reasons': ['required-checks-missing-or-invalid']}

    checks: dict[str, str] = {name: 'pass' for name in REQUIRED_RELEASE_CHECKS}
    details: dict[str, list[str]] = {name: [] for name in REQUIRED_RELEASE_CHECKS}
    rank = {'pass': 0, 'unknown': 1, 'review': 2, 'fail': 3}

    def mark(name: str, result: str, reason: str) -> None:
        if rank[result] > rank[checks[name]]:
            checks[name] = result
        details[name].append(reason)

    from application_audit import audit_traceability, affected_by_changes
    impact = affected_by_changes(doc, attrs.get('changedDependencies', []))
    if impact['unknown']:
        mark('freshness', 'unknown', 'unknown-changed-dependencies: ' + ', '.join(impact['unknown']))
    if policy_attrs.get('completeTraceRequired'):
        trace = audit_traceability(doc, candidate_id=candidate_id)
        for row in trace['rows']:
            if not row['complete']:
                mark('claims', 'unknown', f'{row["requirement"]}: trace-incomplete')

    if candidate['status'] != 'approved':
        mark('freshness', 'review', 'candidate-not-approved')
    if attrs['designRevision'] != doc['design']['revision']:
        mark('freshness', 'review', 'design-revision-mismatch')

    claim_ids = targets(candidate_id, 'requiresClaim')
    if not claim_ids:
        mark('claims', 'unknown', 'no-required-claims')
    evidence_ids: set[str] = set()
    for claim_id in claim_ids:
        if claim_id in impact['affected']:
            mark('freshness', 'review', f'{claim_id}: impacted-by-declared-change')
        if nodes[claim_id]['status'] != 'approved':
            mark('claims', 'review', f'{claim_id}: claim-not-approved')
        argument_ids = targets(claim_id, 'supportedByArgument')
        if len(argument_ids) != 1:
            mark('claims', 'unknown', f'{claim_id}: argument-cardinality')
            continue
        argument = nodes[argument_ids[0]]
        # Relation multiplicity must not turn one observation into several votes.
        premise_ids = list(dict.fromkeys(targets(argument_ids[0], 'hasPremise')))
        evidence_for_claim = [eid for eid in premise_ids if nodes[eid]['kind'] == 'Evidence']
        if not evidence_for_claim or len(evidence_for_claim) != len(premise_ids):
            mark('claims', 'unknown', f'{claim_id}: unsupported-premise-model')
            continue
        values: list[FourValue] = []
        validity: list[str] = []
        for eid in evidence_for_claim:
            evidence_ids.add(eid)
            evidence = nodes[eid]['attributes']
            if nodes[eid]['status'] != 'approved':
                mark('evidence', 'review', f'{eid}: evidence-not-approved')
            if policy_attrs.get('evidenceRegistryRequired'):
                registry = evidence_registry if isinstance(evidence_registry, dict) else {}
                records = registry.get(doc['design']['id'], {})
                record = records.get(eid) if isinstance(records, dict) else None
                fields = ('artifactRef', 'producerRef', 'result', 'subject', 'revision',
                          'environment', 'scope', 'dependencyRefs')
                if 'maxEvidenceAgeSeconds' in policy_attrs:
                    fields += ('observedAt',)
                if record is None:
                    mark('evidence', 'unknown', f'{eid}: registry-record-missing')
                elif not isinstance(record, dict):
                    mark('evidence', 'unknown', f'{eid}: registry-record-invalid')
                elif any(record.get(field, [] if field == 'dependencyRefs' else None)
                         != evidence.get(field, [] if field == 'dependencyRefs' else None)
                         for field in fields):
                    mark('evidence', 'review', f'{eid}: registry-record-mismatch')
            derived = evaluate_applicability(evidence, {
                'subject': attrs['subject'], 'revision': attrs['artifactRevision'],
                'environment': attrs['environmentRef'],
                'requiredScope': nodes[claim_id]['attributes']['scope']},
                changed_dependencies=set(impact['affected']))
            if eid in impact['evidence']:
                derived = {'status': 'needs-review', 'reasons': ['ir-dependency-changed']}
            if 'maxEvidenceAgeSeconds' in policy_attrs:
                observed = evidence.get('observedAt')
                evaluated = attrs.get('evaluatedAt')
                if observed is None or evaluated is None:
                    mark('freshness', 'unknown', f'{eid}: evidence-clock-missing')
                    derived = {'status': 'unknown', 'reasons': ['evidence-clock-missing']}
                else:
                    age = (datetime.fromisoformat(evaluated) - datetime.fromisoformat(observed)).total_seconds()
                    if age < 0 or age > policy_attrs['maxEvidenceAgeSeconds']:
                        mark('freshness', 'review', f'{eid}: evidence-expired-or-future')
                        derived = {'status': 'needs-review', 'reasons': ['evidence-expired-or-future']}
            validity.append(derived['status'])
            recorded = [n for n in doc['nodes'] if n['kind'] == 'EvidenceValidityAssessment'
                        and eid in targets(n['id'], 'assessesEvidence')
                        and claim_id in targets(n['id'], 'forClaim')]
            if len(recorded) != 1:
                mark('evidence', 'unknown', f'{eid}: validity-assessment-cardinality')
            elif recorded[0]['status'] != 'approved':
                mark('evidence', 'review', f'{eid}: validity-assessment-unapproved')
            elif (recorded[0]['attributes']['status'] != derived['status']
                  or recorded[0]['attributes'].get('targetRevision') != attrs['artifactRevision']):
                mark('evidence', 'review', f'{eid}: validity-assessment-stale')
            if derived['status'] == 'needs-review':
                mark('evidence', 'review', f'{eid}: evidence-reassessment-required')
            elif derived['status'] != 'applicable':
                mark('evidence', 'unknown', f'{eid}: {derived["status"]}')
            result = evidence.get('result')
            if result not in ('pass', 'fail', 'unknown'):
                mark('claims', 'unknown', f'{eid}: invalid-evidence-result')
                values.append(FourValue())
            else:
                values.append(FourValue.from_status(
                    ('supported' if result == 'pass' else 'refuted' if result == 'fail'
                     else 'undetermined') if derived['status'] == 'applicable' else 'undetermined'))
        operator = argument['attributes']['operator']
        try:
            argument_value = evaluate_argument(operator, values, argument['attributes'].get('threshold'))
        except ValueError:
            mark('claims', 'unknown', f'{claim_id}: invalid-argument-operator')
            continue
        assessment = assess_claim(argument_value, validity=validity,
                                  reviewed=argument['status'] == 'approved',
                                  required_scope=set(nodes[claim_id]['attributes']['scope']),
                                  covered_scope=set.intersection(*(set(nodes[e]['attributes']['scope'])
                                                                   for e in evidence_for_claim)))
        conclusion = assessment['status']
        recorded = [n for n in doc['nodes'] if n['kind'] == 'AssuranceAssessment'
                    and claim_id in targets(n['id'], 'assessesClaim')]
        if len(recorded) != 1:
            mark('claims', 'unknown', f'{claim_id}: assurance-assessment-cardinality')
            mark('freshness', 'unknown', f'{claim_id}: assurance-assessment-missing')
        else:
            record = recorded[0]
            if record['attributes']['conclusion'] != conclusion or record['status'] != 'approved':
                mark('claims', 'review', f'{claim_id}: assessment-unapproved-or-stale')
            if record['attributes'].get('targetRevision') != attrs['artifactRevision']:
                mark('freshness', 'review', f'{claim_id}: assessment-target-stale')
        if conclusion == 'unsupported':
            mark('claims', 'fail', f'{claim_id}: unsupported')
        elif conclusion == 'review-required':
            mark('claims', 'review', f'{claim_id}: review-required')
        elif conclusion != 'supported':
            mark('claims', 'unknown', f'{claim_id}: indeterminate')
    if not evidence_ids:
        mark('evidence', 'unknown', 'no-linked-evidence')
    if attrs.get('claimsComplete') is not True:
        mark('claims', 'unknown', 'claim-inventory-unconfirmed')
    if attrs.get('changedDependenciesComplete') is not True:
        mark('freshness', 'unknown', 'change-inventory-unconfirmed')
    if attrs.get('findingsComplete') is not True:
        mark('findings', 'unknown', 'finding-inventory-unconfirmed')
    for fid in targets(candidate_id, 'tracksFinding'):
        finding = nodes[fid]['attributes']
        if (finding['disposition'] == 'open'
                and finding['severity'] in policy_attrs['blockingSeverities']):
            mark('findings', 'fail', f'{fid}: blocking-finding')
    if attrs.get('risksComplete') is not True:
        mark('risks', 'unknown', 'risk-inventory-unconfirmed')
    for rid in targets(candidate_id, 'tracksRisk'):
        risk = nodes[rid]['attributes']
        if risk['treatment'] == 'rejected':
            mark('risks', 'fail', f'{rid}: risk-rejected')
        elif (risk['treatment'] != 'accepted' or not risk.get('approvedBy')
              or nodes[rid]['status'] != 'approved'):
            mark('risks', 'review', f'{rid}: approval-pending')
    decision = evaluate_release_gate(checks, required_checks=frozenset(required))
    return {'candidateId': candidate_id, 'policyRef': ref, 'decision': decision,
            'checks': checks, 'details': details,
            'basis': {'requiredClaims': claim_ids, 'evidence': sorted(evidence_ids),
                      'changeImpact': impact,
                      'findings': targets(candidate_id, 'tracksFinding'),
                      'risks': targets(candidate_id, 'tracksRisk')}}


def conformance_report(doc: dict, profile: str='review', catalogs: dict | None=None) -> dict:
    results = validate_graph(doc, profile=profile, catalogs=catalogs)
    error_count = sum(r.severity == 'error' for r in results)
    unresolved = any(r.code == 'external-reference-unresolved' for r in results)
    conclusion = ('non-conformant' if error_count else 'indeterminate' if unresolved
                  else 'structurally-conformant')
    return {
        'conclusion': conclusion,
        'reportVersion': '0.1.0', 'targetSpecification': 'security-design-ir@0.2.0-rc1',
        'profile': profile,
        'modelDigestSHA256': hashlib.sha256(json.dumps(doc, sort_keys=True, ensure_ascii=False).encode()).hexdigest(),
        'summary': {'findings': len(results), 'errors': error_count},
        'findings': [asdict(r) for r in results]
    }
