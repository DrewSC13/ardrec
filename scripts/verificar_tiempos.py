"""Contrastar ambos lectores con oráculos congelados, sin herramientas de evaluación."""
import json
import os
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.messages import MessageError
from ardrec.temporal import correlate_current

def main():
    corpus=json.loads((ROOT/'tests/fixtures/temporal-policy-v1.json').read_text())
    if corpus['policy']!='temporal-v1' or len(corpus['cases'])!=19:raise RuntimeError('Corpus temporal inesperado')
    subprocess.run(['cargo','build','--locked','--example','protocol_probe'],cwd=ROOT,check=True,timeout=300)
    target=Path(os.environ.get('CARGO_TARGET_DIR',ROOT/'target'))
    if not target.is_absolute():target=ROOT/target
    for case in corpus['cases']:
        try:correlate_current(case['request'],case['related']);actual=None
        except MessageError as error:actual=error.code
        expected=case['expected_error']
        if actual!=expected:raise RuntimeError('Oráculo Python: '+case['id'])
        result=subprocess.run([str(target/'debug/examples/protocol_probe')],input=json.dumps({'op':'correlate_current','args':[case['request'],case['related']]}),text=True,capture_output=True,check=True,timeout=10)
        wanted={'ok':True,'value':{}} if expected is None else {'ok':False,'code':expected}
        if json.loads(result.stdout)!=wanted:raise RuntimeError('Oráculo Rust: '+case['id'])
    print('ARDREC_TEMPORAL_ORACLES=19')
    print('ARDREC_TEMPORAL_COMPARISONS=38')
    print('ARDREC_TEMPORAL_PYTHON_RUST_PARITY=PASS')

if __name__=='__main__':main()
