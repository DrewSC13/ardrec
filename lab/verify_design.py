"""Verificación documental; no inspecciona ni configura el anfitrión / Document checks only."""
import ipaddress
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE='d66bb017948fc5e7af1b412729149e27bb423263'
SOURCE='6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72'

def require(ok, message):
    if not ok:raise ValueError(message)

def read(root,path):
    target=root/path
    require(target.is_file() and not any(p.is_symlink() for p in [target,*target.parents]),'Ruta no regular: '+path)
    def pairs(items):
        result={}
        for k,v in items:
            require(k not in result,'Clave JSON duplicada: '+k);result[k]=v
        return result
    return json.loads(target.read_text(encoding='utf-8'),object_pairs_hook=pairs)

def validate(root=ROOT):
    d=read(root,'docs/traceability/laboratory-design-v1.json')
    h=read(root,'lab/host-inventory-v1.json')
    t=read(root,'lab/topology-v1.json')
    a=read(root,'lab/authorization-template-v1.json')
    v=read(root,'lab/verification-plan-v1.json')
    old=read(root,'docs/traceability/point-1-closure-v1.json')
    registry=read(root,'docs/traceability/development-v2.json')
    for obj in [d,h,t,a,v]:require(obj['schema_version']=='1.0','Versión incorrecta')
    require(d['baseline_commit']==BASE and d['source_sha256']==SOURCE,'Procedencia incorrecta')
    require(d['status']=='DESIGN_PREPARED_PENDING_LOCAL_REVIEW_AND_INTEGRATION','Estado documental alterado')
    require(d['development_obligations']==old['development_obligations'],'Obligaciones alteradas')
    require(d['open_findings']==['AL-06','AL-07'],'Hallazgos alterados')
    for key,value in [('physical_isolation','NOT_VERIFIED'),('lab_implementation','NOT_STARTED'),
                      ('experimental_validation','NOT_RUN'),('before_real_executor_gate','BLOCKED_BY_RESIDUAL_OBLIGATIONS')]:
        require(d[key]==value,'Cumplimiento no acreditado: '+key)
    reqs={r['id'] for r in registry['requirements']}
    require(set(d['requirements'])<=reqs,'Requisito desconocido')
    require({'AC-24','AC-25','AC-27','MET-09','MET-10','MET-12'}<=set(d['requirements']),'Falta trazabilidad del laboratorio')
    require(len(d['vms'])==4 and {x['role'] for x in d['vms']}=={'runner','ssh','ftp','smb'},'Roles incorrectos')
    for vm in d['vms']:
        require(all(type(vm[k]) is int and vm[k]>0 for k in ['ram_mib','virtual_disk_gib','vcpus']),'Recursos inválidos')
    p=d['resource_profile']
    require(sum(x['ram_mib'] for x in d['vms'])<=p['vm_ram_ceiling_mib']==6144,'Exceso de RAM')
    require(p['host_reserve_mib']>=5120 and p['start_available_memory_mib']>=7680 and p['runtime_available_memory_floor_mib']>=2048,'Reserva de RAM reducida')
    require(sum(x['virtual_disk_gib'] for x in d['vms'])==52 and p['lab_allocated_disk_budget_gib']==80 and p['host_free_disk_floor_gib']>=40,'Presupuesto de disco incoherente')
    require(p['max_active_environment_sets']==t['max_active_environments']==1 and p['technical_attempt_concurrency']==1,'Concurrencia incompatible')
    require(h['status']=='USER_REPORTED_READ_ONLY_NOT_INDEPENDENTLY_MEASURED' and h['kvm_usable_by_operator']=='NOT_TESTED','Inventario sobreatribuido')
    require(h['public_addresses_omitted'] is True,'Inventario público sin minimización')
    require(t['status']=='DESIGN_ONLY_NOT_DEPLOYED' and t['default_policy']=='DENY','Política de red incorrecta')
    for key in ['runner_forwarding','target_to_target','internet_during_measurement','management_nic_during_measurement']:
        require(t[key] is False,'Apertura de red no autorizada: '+key)
    nets=t['networks'];require(len(nets)==9 and len({n['id'] for n in nets})==9,'Inventario de redes incorrecto')
    require({(n['environment'],n['protocol']) for n in nets}=={(e,p) for e in ['dev','pilot','exp'] for p in ['ssh','ftp','smb']},'Falta separación')
    observed=[ipaddress.ip_network(x) for x in h['existing_ipv4_networks']]
    proposed=[]
    for n in nets:
        net=ipaddress.ip_network(n['cidr'])
        require(net.version==4 and net.prefixlen==28 and net.subnet_of(ipaddress.ip_network('10.0.0.0/8')),'Red no prevista')
        require(not any(net.overlaps(x) for x in observed+proposed),'Redes superpuestas')
        proposed.append(net)
        require(n['status']=='RESERVED_DESIGN_RECHECK_BEFORE_DEPLOYMENT','Reserva presentada como desplegada')
        require(all(n[k] is None for k in ['forward','host_ip','physical_uplink','default_gateway']),'Ruta/pasarela inesperada')
        require(all(n[k] is False for k in ['dhcp','dns','ipv6']),'Servicio de red inesperado')
        require(ipaddress.ip_address(n['runner'])==net.network_address+1 and ipaddress.ip_address(n['target'])==net.network_address+2,'IP de rol incorrecta')
    require(t['allowed_new_connections']==[
        {'source':'runner','destination':'ssh_target','transport':'tcp','ports':[22]},
        {'source':'runner','destination':'ftp_target','transport':'tcp','ports':[21],'port_ranges':[[50000,50009]]},
        {'source':'runner','destination':'smb_target','transport':'tcp','ports':[445]}],'Puertos ampliados sin revisión')
    require(a['status']=='TEMPLATE_NOT_AUTHORIZATION' and a['execution_enabled'] is False,'Plantilla confundida con autorización')
    require(all(a[k] is None for k in ['authorization_id','legitimate_owner','operator','approved_at','valid_from','valid_until','environment','limits','stop_contact','approval_evidence_ref']),'Autorización inventada')
    require(all(a[k]==[] for k in ['service_scenario_ids','vm_uuids','destinations','ports','case_ids','profile_hashes','credential_refs','resource_paths','cleanup_resources']),'Plantilla materializada')
    require(v['status']=='PLANNED_NOT_EXECUTED','Plan presentado como ejecutado')
    ids=[x['id'] for x in v['checks']]
    require(ids==d['related_checks']==[f'LAB-V{i:02d}' for i in range(1,13)],'Comprobaciones incompletas')
    obligations={o['id'] for o in old['development_obligations']}
    for x in v['checks']:
        require(x['status']=='NOT_RUN' and x['evidence']==[],'Prueba física inventada')
        require(set(x['requirements'])<=reqs and set(x['obligations'])<=obligations,'Vínculo desconocido')
        require(x['es'] and x['en'] and 4<=x['roadmap_step']<=33,'Plan incompleto')
    for path in d['documents']:
        require('..' not in Path(path).parts and not Path(path).is_absolute() and (root/path).is_file(),'Documento ausente/externo')
    workflow=(root/'.github/workflows/ci.yml').read_text()
    require(workflow.count('run: python3 lab/verify_design.py')==1,'Falta comprobación documental en CI')
    return {'status':'PASS_DOCUMENT_CONSISTENCY_ONLY','networks':9,'vm_ram_mib':sum(x['ram_mib'] for x in d['vms']),
        'planned_checks':12,'physical_verification':'NOT_RUN','real_execution':'NOT_AUTHORIZED_BY_THIS_DESIGN'}

if __name__=='__main__':
    try:
        print(json.dumps(validate(),ensure_ascii=False,indent=2))
        print('ARDREC_LAB_DESIGN_DOCUMENTS=PASS')
    except (ValueError,KeyError,TypeError,OSError) as error:
        print('ARDREC_LAB_DESIGN_DOCUMENTS=FAIL: '+str(error));raise SystemExit(1)
