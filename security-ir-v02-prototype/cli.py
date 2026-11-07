"""CLI: python cli.py validate fixtures/order_cancel_valid.json --profile review --catalogs fixtures/catalogs.json"""
import argparse
import json
from pathlib import Path
from engine import conformance_report, evaluate_release_candidate

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=['validate','release-gate'])
    parser.add_argument('document')
    parser.add_argument('--profile',choices=['draft','review','release'],default='review')
    parser.add_argument('--catalogs')
    parser.add_argument('--evidence-registry', help='Independent evidence records for policies that require them')
    parser.add_argument('--output')
    parser.add_argument('--candidate', help='ReleaseCandidate ID for release-gate')
    args=parser.parse_args()
    doc=json.loads(Path(args.document).read_text(encoding='utf-8'))
    catalogs=json.loads(Path(args.catalogs).read_text(encoding='utf-8')) if args.catalogs else None
    evidence_registry=json.loads(Path(args.evidence_registry).read_text(encoding='utf-8')) if args.evidence_registry else None
    if args.command == 'release-gate':
        if not args.candidate:
            parser.error('--candidate is required for release-gate')
        report=evaluate_release_candidate(doc,args.candidate,catalogs=catalogs,
                                          evidence_registry=evidence_registry)
        exit_code={'ready':0,'blocked':1,'review-required':2,'unknown':2}[report['decision']]
    else:
        report=conformance_report(doc,args.profile,catalogs)
        exit_code={'structurally-conformant':0, 'non-conformant':1, 'indeterminate':2}[report['conclusion']]
    payload=json.dumps(report,indent=2,ensure_ascii=False)+'\n'
    if args.output:
        Path(args.output).write_text(payload,encoding='utf-8')
    else:
        print(payload)
    raise SystemExit(exit_code)

if __name__=='__main__':main()
