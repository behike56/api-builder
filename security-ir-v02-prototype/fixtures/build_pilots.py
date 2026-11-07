"""Rebuild three synthetic API design pilots from the small release-candidate IR."""
import copy
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = json.loads((HERE / 'release_candidate_valid.json').read_text())
next(n for n in BASE['nodes'] if n['id'] == 'RP-001')['attributes'].update(
    evidenceRegistryRequired=True, completeTraceRequired=True)


def n(doc, id):
    return next(x for x in doc['nodes'] if x['id'] == id)


def link(doc, kind, source, target):
    doc['relations'].append({'id': f'PILOT-{len(doc["relations"])+1:03}', 'kind': kind,
                             'source': source, 'target': target})


def complete_path(doc, suffix, requirement, asset, control, criterion, evidence, claim, scenario):
    threat = f'TH-{suffix}'
    activity = f'VA-{suffix}'
    doc['nodes'].extend([
        {'id': threat, 'kind': 'ThreatScenario', 'status': 'approved',
         'attributes': {'scenario': scenario}},
        {'id': activity, 'kind': 'VerificationActivity', 'status': 'approved',
         'attributes': {'method': 'synthetic security test', 'executionStatus': 'passed'}}])
    link(doc, 'threatens', threat, asset)
    link(doc, 'mitigates', control, threat)
    link(doc, 'verifies', activity, criterion)
    link(doc, 'generatedBy', evidence, activity)
    link(doc, 'claimsFor', claim, requirement)


def save(name, doc):
    (HERE / name).write_text(json.dumps(doc, ensure_ascii=False, indent=2) + '\n')

order = copy.deepcopy(BASE)
complete_path(order, 'ORDER', 'SR-003', 'AST-001', 'CA-001', 'VC-001',
              'EVD-001', 'CLAIM-001', 'Cross-tenant order cancellation')
save('pilot_order_cancel.json', order)

sensitive = copy.deepcopy(order)
sensitive['design']['id'] = 'sensitive-record-read-api'
n(sensitive, 'AST-001')['attributes']['name'] = 'Confidential customer record'
n(sensitive, 'SR-003')['attributes']['statement'] = 'Only permitted case workers can read records in their tenant'
n(sensitive, 'CMP-001')['attributes']['name'] = 'ReadRecordService.authorize'
n(sensitive, 'VC-001')['attributes']['statement'] = 'Deny cross-tenant or wrong-role read without disclosing fields'
n(sensitive, 'RC-001')['attributes']['subject'] = 'readSensitiveRecord'
n(sensitive, 'CLAIM-001')['attributes']['statement'] = 'Sensitive reads enforce tenant and role permissions'
n(sensitive, 'EVD-001')['attributes']['subject'] = 'readSensitiveRecord'
n(sensitive, 'TH-ORDER')['attributes']['scenario'] = 'BOPLA: record fields exposed to unauthorized role'
save('pilot_sensitive_read.json', sensitive)

approval = copy.deepcopy(order)
approval['design']['id'] = 'multistage-approval-api'
n(approval, 'AST-001')['attributes']['name'] = 'Approval request'
n(approval, 'SR-003')['attributes']['statement'] = 'Requester cannot perform first approval'
n(approval, 'CMP-001')['attributes']['name'] = 'FirstApprovalService.authorize'
n(approval, 'VC-001')['attributes']['statement'] = 'Reject requester self-approval'
n(approval, 'RC-001')['attributes']['subject'] = 'approveRequest'
n(approval, 'CLAIM-001')['attributes']['statement'] = 'First approval separates requester and approver'
n(approval, 'EVD-001')['attributes']['subject'] = 'approveRequest'
n(approval, 'TH-ORDER')['attributes']['scenario'] = 'Requester self-approval'
for old, new in [('SR-003','SR-004'),('CA-001','CA-002'),('CMP-001','CMP-002'),
                 ('VC-001','VC-002'),('CLAIM-001','CLAIM-002'),('ARG-001','ARG-002'),
                 ('EVD-001','EVD-002'),('EVA-001','EVA-002'),('AA-001','AA-002')]:
    clone = copy.deepcopy(n(approval, old)); clone['id'] = new; approval['nodes'].append(clone)
n(approval, 'SR-004')['attributes']['statement'] = 'Final approver differs from requester and first approver'
n(approval, 'CMP-002')['attributes']['name'] = 'FinalApprovalService.authorize'
n(approval, 'VC-002')['attributes']['statement'] = 'Reject reused approver and out-of-order transition'
n(approval, 'CLAIM-002')['attributes']['statement'] = 'Final approval enforces separation and order'
for kind, source, target in [
    ('protects','SR-004','AST-001'),('addresses','CA-002','SR-004'),
    ('enforcedAt','CA-002','CMP-002'),('evaluates','VC-002','SR-004'),
    ('requiresClaim','RC-001','CLAIM-002'),('supportedByArgument','CLAIM-002','ARG-002'),
    ('hasPremise','ARG-002','EVD-002'),('assessesEvidence','EVA-002','EVD-002'),
    ('forClaim','EVA-002','CLAIM-002'),('assessesClaim','AA-002','CLAIM-002')]:
    link(approval, kind, source, target)
complete_path(approval, 'FINAL', 'SR-004', 'AST-001', 'CA-002', 'VC-002',
              'EVD-002', 'CLAIM-002', 'Final approval by same person or before first stage')
save('pilot_multistage_approval.json', approval)
