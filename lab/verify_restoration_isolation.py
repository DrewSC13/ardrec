"""Verify the reviewed public record, without accessing any VM or private file."""
import hashlib,json
from pathlib import Path
EXPECTED_SHA256='3c21d24013519ef41cee302df8069ab170bb4c10fc55a7a178adcf7fcee918b7'
def verify(root=None):
    root=Path(root) if root is not None else Path(__file__).resolve().parents[1]
    raw=(root/'lab/restoration-isolation-v1/record.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=EXPECTED_SHA256:raise ValueError('Reviewed restoration/isolation record changed')
    r=json.loads(raw)
    plan=json.loads((root/'lab/verification-plan-v1.json').read_bytes())
    expected={x['id'] for x in plan['checks'] if x['roadmap_step']==5}
    if set(r['checks'])!=expected:raise ValueError('Point 5 coverage differs from historical plan')
    for name in ('README.md','record.json'):
        if not (root/'lab/restoration-isolation-v1'/name).is_file():raise ValueError('Missing documentation')
    return {'status':'PASS_DOCUMENT_CONSISTENCY_ONLY','physical_reexecution':'NOT_RUN','scope':r['scope'],'checks':sorted(expected)}
if __name__=='__main__':print(json.dumps(verify(),sort_keys=True))
