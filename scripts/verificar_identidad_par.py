"""Identidad de ambos procesos sobre conexión Unix nueva, sin ejecutar herramientas."""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests/unit'),str(ROOT/'scripts')]
from ardrec.messages import encode_message
from ardrec.peer_identity import PeerIdentity
from ardrec.reconciliation import begin_query,inspect_recovery
from ardrec.reconciliation_transport import exchange_query,ExchangeError
from test_persistence import INITIAL,DurableStore,prepare,reserve,reopen
from verificar_diario_tecnico import probe,require
from verificar_conciliacion_transporte import line,stop

def inventory(path):return {str(p.relative_to(path)):p.read_bytes() for p in path.rglob('*') if p.is_file()}

def verify(journal_binary,peer_binary):
    fixtures=json.loads((ROOT/'tests/fixtures/messages-temporal-v1.json').read_text())
    with tempfile.TemporaryDirectory(prefix='ardrec-peer-') as temporary:
        root=Path(temporary)
        for label in ('accepted','python_pid','python_uid','python_gid','rust_pid','rust_uid','rust_gid'):
            directory=root/label;directory.mkdir(mode=0o700)
            rust,python,path=directory/'rust',directory/'python',directory/'socket'
            probe(journal_binary,'create',rust);probe(journal_binary,'register',rust,fixtures['request'])
            result=deepcopy(fixtures['result_completed'])
            result['payload']['snapshot']['journal_reference']=probe(journal_binary,'inspect',rust)['snapshot']['journal_reference']
            probe(journal_binary,'report',rust,result)
            with DurableStore.create(python,INITIAL) as store:
                prepare(store);reserve(store);begin_query(store,message_id='QUERY-PEER',created_at='2026-10-19T12:00:20Z')
            before_python,before_rust=inventory(python),inventory(rust)
            server_policy=[os.getpid(),os.geteuid(),os.getegid()]
            if label.startswith('rust_'):
                field=('pid','uid','gid').index(label.split('_')[1]);server_policy[field]=server_policy[field]+1 if field==0 else server_policy[field]^1
            child=subprocess.Popen([str(peer_binary),str(rust),str(path),*map(str,server_policy)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                try:line(child,'READY')
                except Exception as error:
                    _,stderr=stop(child)
                    raise RuntimeError(str(error)+'; Rust: '+stderr) from error
                client_policy=[child.pid,os.geteuid(),os.getegid()]
                if label.startswith('python_'):
                    field=('pid','uid','gid').index(label.split('_')[1]);client_policy[field]=client_policy[field]+1 if field==0 else client_policy[field]^1
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                    connection.settimeout(5);connection.connect(str(path))
                    with reopen(python) as store:
                        before=inspect_recovery(store)
                        if label=='accepted':
                            received=exchange_query(store,connection,expected_peer=PeerIdentity(*client_policy))
                            require(received.result==encode_message(result),'Resultado distinto')
                            require(not received.new_execution_authorized,'Despacho inesperado')
                        else:
                            try:exchange_query(store,connection,expected_peer=PeerIdentity(*client_policy))
                            except ExchangeError as error:
                                if label.startswith('python_'):require(error.code=='peer_identity_mismatch','Causa de rechazo distinta')
                            else:raise RuntimeError('Par no autorizado aceptado')
                            require(inspect_recovery(store)==before,'Consulta alterada')
                            require(not before.new_execution_authorized,'Ejecución habilitada')
                out,err=child.communicate(timeout=10)
                if label=='accepted':
                    require(child.returncode==0 and 'DONE' in out,'Falló intercambio: '+err)
                    with reopen(python) as store:require(inspect_recovery(store)==received,'Recuperación distinta')
                else:
                    require(child.returncode!=0,'Rust no rechazó intercambio incompleto')
                    if label.startswith('rust_'):require('peer_identity_mismatch' in err,'Rust rechazó por otra causa')
                    require(inventory(python)==before_python,'Cambió diario Python')
                    require(inventory(rust)==before_rust,'Cambió diario Rust')
                print('ARDREC_PEER_SCENARIO='+label+':PASS',flush=True)
            finally:stop(child)
    print('ARDREC_PEER_IDENTITY_INTEGRATION=PASS',flush=True)

def main():
    require(len(sys.argv) in (1,3),'Usar sin argumentos o con las dos sondas')
    if len(sys.argv)==3:
        verify(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve());return
    with tempfile.TemporaryDirectory(prefix='ardrec-peer-build-') as directory:
        env=dict(os.environ,CARGO_TARGET_DIR=str(Path(directory)/'target'),CARGO_TERM_COLOR='never')
        subprocess.run(['cargo','build','--locked','--offline','--package','ardrec-executor','--example','journal_probe','--example','peer_query_probe'],cwd=ROOT,env=env,check=True,timeout=300)
        folder=Path(directory)/'target/debug/examples';verify(folder/'journal_probe',folder/'peer_query_probe')

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('ARDREC_PEER_IDENTITY_INTEGRATION=FAIL: '+ascii(str(error)),flush=True);raise SystemExit(1)
