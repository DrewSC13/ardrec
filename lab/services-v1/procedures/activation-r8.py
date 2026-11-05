#!/usr/bin/env python3
"""ARDREC development activation R8 / Activación temporal de desarrollo.
Creates only named lab objects, tests fixed synthetic resources, then stops them.
Root is required for libvirt and dedicated bridge rules. Never run tests externally.
"""
import ast,base64,datetime,fcntl,grp,hashlib,ipaddress,json,os,pwd,re,shutil,signal,stat,subprocess,sys,time,uuid
from pathlib import Path
import xml.etree.ElementTree as ET
BASE='93e1f4cdaff1bca621214d3a27798889baf03a86'
REPO=Path('/home/cicada/Development/GitHub/ardrec')
LAB=Path('/home/cicada/ardrec-lab')
BUILD=LAB/'builds/dev-roles-v2'
RECEIPT_SHA='46f4ceb8adffd5010714d0b365f46f96fc15fc8b8e7cb9585b15c13161890f3b'
STORE=Path('/var/lib/libvirt/images/ardrec-dev-point4-v6')
WORK=Path('/var/lib/ardrec-point4-activation-v6')
TABLE='ardrec_dev_point4_v1';CHAIN='ARDREC_DEV_P4_V1'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C','HOME':'/root','LIBVIRT_DEFAULT_URI':'qemu:///system','LIBGUESTFS_BACKEND':'direct'}
AUDIT="import hashlib,json,os,subprocess,sys,time\nfrom pathlib import Path\nexpected=json.loads(sys.argv[1]);role=expected['role']\ndef run(args):\n p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)\n if p.returncode:raise RuntimeError('Command failed: '+args[0]+': '+p.stderr.decode(errors='replace')[-1500:])\n return p.stdout.decode()\ndef require(ok,msg):\n if not ok:raise RuntimeError(msg)\nrequire(Path('/etc/machine-id').read_text().strip()==expected['machine_id'],'Machine identity mismatch')\npackages={}\nfor name,version in expected['package_versions'].items():\n actual=run(['dpkg-query','-W','-f=${Version}',name]).strip()\n require(actual==version,'Package version differs: '+name);packages[name]=actual\nfor p,digest in expected['config_sha256'].items():require(hashlib.sha256(Path(p).read_bytes()).hexdigest()==digest,'Configuration changed: '+p)\nfor p in ['net/ipv4/ip_forward','net/ipv6/conf/all/forwarding']:\n require(Path('/proc/sys/'+p).read_text().strip()=='0','Forwarding enabled')\nrequire(Path('/proc/sys/net/ipv6/conf/all/disable_ipv6').read_text().strip()=='1','IPv6 enabled')\n# Wait only for boot network configuration; never repeat a service test.\nwant={n['ip'] for n in expected['network']}\nfor i in range(20):\n addr=json.loads(run(['ip','-j','address','show']))\n got={a['local'] for interface in addr if interface['ifname']!='lo' for a in interface.get('addr_info',[]) if a['family']=='inet'}\n if got==want:break\n time.sleep(1)\nrequire(got==want,'Guest addresses differ')\nfor family in ['-4','-6']:\n routes=json.loads(run(['ip',family,'-j','route','show','table','all']))\n require(not any(r.get('dst','default')=='default' or r.get('gateway') for r in routes),'Guest has default/gateway route')\nrun(['systemctl','is-active','nftables.service'])\nrules=json.loads(run(['nft','-j','list','ruleset']))\nchains=[x['chain'] for x in rules['nftables'] if 'chain' in x and x['chain'].get('table')=='ardrec_guest']\nrequire({c['name'] for c in chains}=={'input','output','forward'} and all(c['policy']=='drop' for c in chains),'Guest firewall policy differs')\nfor unit in expected['services_masked']:\n p=Path('/etc/systemd/system')/unit\n require(p.is_symlink() and os.readlink(p)=='/dev/null','Service not masked: '+unit)\nprint(json.dumps({'role':role,'identity':'PASS','config_hashes':'PASS','addresses':sorted(got),'forwarding':'DISABLED','default_routes':'ABSENT','guest_firewall':'ACTIVE_DEFAULT_DROP','service_masks':'PASS','utc_ns':time.time_ns(),'kernel':os.uname().release,'package_versions':packages}))\n"
START="import json,re,subprocess,sys,time\nrole=sys.argv[1]\nunit={'ssh':'ssh.service','ftp':'vsftpd.service','smb':'smbd.service'}[role]\nendpoint={'ssh':'0.0.0.0:22','ftp':'10.203.31.2:21','smb':'10.203.32.2:445'}[role]\n\ndef run(args):\n p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)\n if p.returncode:raise RuntimeError(p.stdout.decode(errors='replace')[-3000:])\n return p.stdout.decode()\n\ndef sample():\n fields=run(['systemctl','show',unit,'--property=ActiveState,SubState,MainPID,ExecMainStatus,NRestarts'])\n state=dict(line.split('=',1) for line in fields.splitlines() if '=' in line)\n listeners=run(['ss','-H','-lntp'])\n pid=int(state.get('MainPID','0'))\n rows=[x for x in listeners.splitlines() if len(x.split())>=5 and x.split()[3]==endpoint]\n ready=state.get('ActiveState')=='active' and state.get('SubState')=='running' and pid>0 and any(re.search(r'\\bpid='+str(pid)+r'[,)]',row) for row in rows)\n return state,listeners,pid,ready\n\ntry:\n run(['systemctl','unmask',unit]);run(['systemctl','start',unit])\n previous=None;stable=0;samples=[]\n for attempt in range(20):\n  state,listeners,pid,ready=sample();samples.append({'state':state,'listener_ready':ready})\n  if state.get('ActiveState')=='failed':raise RuntimeError('Service exited before readiness: '+json.dumps(state))\n  stable=stable+1 if ready and pid==previous else (1 if ready else 0);previous=pid\n  if stable>=3:break\n  time.sleep(1)\n else:raise RuntimeError('No stable listener at '+endpoint)\n print(json.dumps({'role':role,'unit':unit,'status':'READY_STABLE_LISTENER','endpoint':endpoint,'pid':pid,'consecutive_samples':stable,'listeners':listeners,'samples':samples}))\nexcept Exception as error:\n diagnostics={}\n for name,args in [('status',['systemctl','status',unit,'--no-pager','--full']),('journal',['journalctl','-b','-u',unit,'--no-pager','-n','60'])]:\n  try:\n   p=subprocess.run(args,capture_output=True,timeout=15);diagnostics[name]=(p.stdout+p.stderr).decode(errors='replace')[-12000:]\n  except Exception as e:diagnostics[name]=str(e)\n print(json.dumps({'role':role,'unit':unit,'status':'NOT_READY','error':str(error),'diagnostics':diagnostics}))\n"
SMOKE='try:\n """One bounded development service smoke, no experiment or algorithm execution."""\n import ftplib,hashlib,json,os,pwd,subprocess,tempfile,uuid\n from pathlib import Path\n creds=json.loads(Path(\'/root/ardrec-development-credentials.json\').read_text())\n user=pwd.getpwnam(\'ardrec-operator\');results=[];marker=\'ardrec-smoke-\'+uuid.uuid4().hex+\'.txt\'\n content=b\'ARDREC DEVELOPMENT SERVICE SMOKE V1\\n\'\n def require(ok,message):\n  if not ok:raise RuntimeError(message)\n def run(label,args,input=None,denied=None):\n  p=subprocess.run([\'runuser\',\'-u\',\'ardrec-operator\',\'--\',*args],input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=35,env={\'PATH\':\'/usr/sbin:/usr/bin:/sbin:/bin\',\'HOME\':user.pw_dir,\'LC_ALL\':\'C\'})\n  output=p.stdout+p.stderr\n  require(len(output)<262144,\'Output limit\')\n  if denied is None:require(p.returncode==0,label+\': \'+output.decode(errors=\'replace\')[-1500:])\n  else:require(p.returncode!=0 and any(x in output for x in denied),label+\': expected explicit denial\')\n  results.append({\'check\':label,\'result\':\'PASS\',\'exit_code\':p.returncode,\'output_sha256\':hashlib.sha256(output).hexdigest()})\n  return p.stdout\n ssh=[\'ssh\',\'-F\',\'/dev/null\',\'-o\',\'BatchMode=yes\',\'-o\',\'StrictHostKeyChecking=yes\',\'-o\',\'UserKnownHostsFile=\'+user.pw_dir+\'/.ssh/known_hosts\',\'-o\',\'ConnectTimeout=8\',\'-o\',\'ConnectionAttempts=1\',\'-i\',user.pw_dir+\'/.ssh/id_ed25519\',\'ardrec_ssh@10.203.30.2\']\n # Fixed commands only. Remote marker is generated as hex and never supplied by a user.\n require(run(\'ssh-identity\',ssh+[\'id -un\']).strip()==b\'ardrec_ssh\',\'SSH identity differs\')\n require(run(\'ssh-reference\',ssh+[\'cat /srv/ardrec/ssh/read-only/reference.txt\'])==b\'ARDREC DEV SSH REFERENCE V1\\n\',\'SSH fixture differs\')\n require(run(\'ssh-limited-helper\',ssh+[\'sudo -n /usr/local/libexec/ardrec-identidad\']).strip()==b\'0\',\'Limited helper differs\')\n run(\'ssh-restricted-denied\',ssh+[\'cat /srv/ardrec/ssh/restricted/denied.txt\'],denied=[b\'Permission denied\'])\n path=\'/srv/ardrec/ssh/temporary/\'+marker\n try:\n  run(\'ssh-write\',ssh+[\'umask 077; set -C; cat > \'+path],input=content)\n  require(run(\'ssh-read-marker\',ssh+[\'cat \'+path])==content,\'SSH marker differs\')\n finally:\n  run(\'ssh-cleanup\',ssh+[\'rm -f -- \'+path+\' && test ! -e \'+path])\n # FTP negative control must receive an application denial, not a timeout.\n f=ftplib.FTP();f.connect(\'10.203.31.2\',21,timeout=8)\n try:\n  try:f.login(creds[\'ftp\'][\'username\'],creds[\'ftp\'][\'password\'])\n  except ftplib.error_perm as error:require(str(error).startswith(\'530\'),\'Unexpected cleartext denial\')\n  else:raise RuntimeError(\'FTP accepted cleartext login\')\n  results.append({\'check\':\'ftp-cleartext-login-denied\',\'result\':\'PASS\'})\n finally:f.close()\n with tempfile.TemporaryDirectory(prefix=\'ardrec-smoke-\',dir=\'/run\') as td:\n  root=Path(td);os.chown(root,user.pw_uid,user.pw_gid);root.chmod(0o700)\n  local=root/marker;local.write_bytes(content);os.chown(local,user.pw_uid,user.pw_gid);local.chmod(0o600)\n  cfg=(\'user = "\'+creds[\'ftp\'][\'username\']+\':\'+creds[\'ftp\'][\'password\']+\'"\\n\').encode()\n  curl=[\'curl\',\'--silent\',\'--show-error\',\'--fail\',\'--connect-timeout\',\'8\',\'--max-time\',\'25\',\'--ssl-reqd\',\'--cacert\',\'/etc/ardrec/tls/ca.crt\',\'--ftp-pasv\',\'--config\',\'-\']\n  url=\'ftp://10.203.31.2/\'\n  require(run(\'ftps-reference\',curl+[url+\'read-only/reference.txt\'],input=cfg)==b\'ARDREC DEV FTP REFERENCE V1\\n\',\'FTPS fixture differs\')\n  uploaded=False\n  try:\n   run(\'ftps-write\',curl+[\'--upload-file\',str(local),url+\'temporary/\'+marker],input=cfg);uploaded=True\n   require(run(\'ftps-read-marker\',curl+[url+\'temporary/\'+marker],input=cfg)==content,\'FTPS marker differs\')\n  finally:\n   if uploaded:run(\'ftps-cleanup\',curl+[\'--quote\',\'DELE /temporary/\'+marker,\'--list-only\',url+\'temporary/\'],input=cfg)\n  auth=root/\'smb.auth\';auth.write_text(\'username = \'+creds[\'smb\'][\'username\']+\'\\npassword = \'+creds[\'smb\'][\'password\']+\'\\ndomain = ARDREC\\n\');os.chown(auth,user.pw_uid,user.pw_gid);auth.chmod(0o600)\n  smb=[\'smbclient\',\'-A\',str(auth),\'-m\',\'SMB3\',\'--client-protection=sign\',\'-t\',\'15\']\n  download=root/\'reference.txt\'\n  run(\'smb-reference\',smb+[\'//10.203.32.2/read-only\',\'-c\',\'get reference.txt \'+str(download)])\n  require(download.read_bytes()==b\'ARDREC DEV SMB REFERENCE V1\\n\',\'SMB fixture differs\')\n  run(\'smb-restricted-denied\',smb+[\'//10.203.32.2/restricted\',\'-c\',\'ls\'],denied=[b\'NT_STATUS_ACCESS_DENIED\'])\n  # Share requires encryption; client explicitly requests it too.\n  enc=[\'smbclient\',\'-A\',str(auth),\'-m\',\'SMB3\',\'--client-protection=encrypt\',\'-t\',\'15\',\'//10.203.32.2/temporary\']\n  uploaded=False\n  try:\n   run(\'smb-encrypted-write\',enc+[\'-c\',\'put \'+str(local)+\' \'+marker]);uploaded=True\n   dest=root/\'smb-marker.txt\';run(\'smb-encrypted-read\',enc+[\'-c\',\'get \'+marker+\' \'+str(dest)])\n   require(dest.read_bytes()==content,\'SMB marker differs\')\n  finally:\n   if uploaded:run(\'smb-cleanup\',enc+[\'-c\',\'del \'+marker])\n print(json.dumps({\'status\':\'DEVELOPMENT_SMOKE_PASS\',\'checks\':results,\'marker\':marker,\'experimental_data\':False}))\nexcept Exception as error:\n print(json.dumps({\'status\':\'DEVELOPMENT_SMOKE_FAILED\',\'checks\':globals().get(\'results\',[]),\'marker\':globals().get(\'marker\'),\'error\':str(error),\'experimental_data\':False}))\n'
EXPECTED={'ftp': {'image_sha256': '134f0f24cfb3d69b65e0cea1b94b0d35e14ceff77e4c31fd188a208fc4e7540c', 'resources': {'disk_gib': 8, 'nics': [{'ip': '10.203.31.2', 'mac': '52:54:00:ad:31:02', 'network': 'ardrec-dev-ftp'}], 'ram_mib': 768, 'vcpus': 1}}, 'runner': {'image_sha256': 'bef3f92f221735b8ce6fc0f33f3fb2163585839557302384e3b62db343173e4b', 'resources': {'disk_gib': 24, 'nics': [{'ip': '10.203.30.1', 'mac': '52:54:00:ad:30:01', 'network': 'ardrec-dev-ssh'}, {'ip': '10.203.31.1', 'mac': '52:54:00:ad:31:01', 'network': 'ardrec-dev-ftp'}, {'ip': '10.203.32.1', 'mac': '52:54:00:ad:32:01', 'network': 'ardrec-dev-smb'}], 'ram_mib': 3072, 'vcpus': 2}}, 'smb': {'image_sha256': '4f1dd47c61afd5a1dce1d3d3bfc17d59c966c2763c6c5ae1e29cbf6e5219184d', 'resources': {'disk_gib': 12, 'nics': [{'ip': '10.203.32.2', 'mac': '52:54:00:ad:32:02', 'network': 'ardrec-dev-smb'}], 'ram_mib': 1536, 'vcpus': 2}}, 'ssh': {'image_sha256': 'efcb710d227a93d2feeb28fff874ddfbb7969e289cb8059c9f912aec988a7593', 'resources': {'disk_gib': 8, 'nics': [{'ip': '10.203.30.2', 'mac': '52:54:00:ad:30:02', 'network': 'ardrec-dev-ssh'}], 'ram_mib': 768, 'vcpus': 1}}}

def require(ok,msg):
 if not ok:raise RuntimeError(msg)
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024**2),b''):h.update(chunk)
 return h.hexdigest()
def regular(path,uid):
 require(not any(p.is_symlink() for p in [path,*path.parents]),'Ruta enlazada: '+str(path))
 s=path.stat();require(stat.S_ISREG(s.st_mode) and s.st_uid==uid and s.st_nlink==1,'Archivo no regular/propio: '+str(path))
def private(path):
 require(not any(p.is_symlink() for p in [path,*path.parents]),'Ruta enlazada: '+str(path))
 path.mkdir(mode=0o700,exist_ok=False)
def write(path,value):
 raw=value.encode() if isinstance(value,str) else value
 with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def allocated(root):
 total=0;seen=set()
 if not root.exists():return 0
 for parent,dirs,files in os.walk(root,followlinks=False):
  for n in files:
   s=(Path(parent)/n).lstat();key=(s.st_dev,s.st_ino)
   if key not in seen:total+=s.st_blocks*512;seen.add(key)
 return total

def network_xml(role,uid):
 n=ET.Element('network',{'ipv6':'no'});ET.SubElement(n,'name').text='ardrec-dev-'+role;ET.SubElement(n,'uuid').text=uid
 ET.SubElement(n,'bridge',{'name':{'ssh':'brad30','ftp':'brad31','smb':'brad32'}[role],'stp':'off','delay':'0'})
 ET.SubElement(n,'dns',{'enable':'no'})
 return ET.tostring(n,encoding='unicode')
def domain_xml(role,spec,uid,disk):
 d=ET.Element('domain',{'type':'kvm'});ET.SubElement(d,'name').text='ardrec-dev-'+role;ET.SubElement(d,'uuid').text=uid
 for tag in ['memory','currentMemory']:ET.SubElement(d,tag,{'unit':'MiB'}).text=str(spec['ram_mib'])
 ET.SubElement(d,'vcpu',{'placement':'static'}).text=str(spec['vcpus'])
 osel=ET.SubElement(d,'os');ET.SubElement(osel,'type',{'arch':'x86_64','machine':'pc-i440fx-11.1'}).text='hvm';ET.SubElement(osel,'boot',{'dev':'hd'})
 features=ET.SubElement(d,'features');ET.SubElement(features,'acpi');ET.SubElement(features,'apic')
 ET.SubElement(d,'cpu',{'mode':'host-model'});ET.SubElement(d,'clock',{'offset':'utc'})
 for tag in ['on_poweroff','on_reboot','on_crash']:ET.SubElement(d,tag).text='destroy'
 pm=ET.SubElement(d,'pm');ET.SubElement(pm,'suspend-to-mem',{'enabled':'no'});ET.SubElement(pm,'suspend-to-disk',{'enabled':'no'})
 devices=ET.SubElement(d,'devices');ET.SubElement(devices,'emulator').text='/usr/bin/qemu-system-x86_64'
 drive=ET.SubElement(devices,'disk',{'type':'file','device':'disk'});ET.SubElement(drive,'driver',{'name':'qemu','type':'qcow2','cache':'none','io':'native'});ET.SubElement(drive,'source',{'file':str(disk)});ET.SubElement(drive,'target',{'dev':'vda','bus':'virtio'})
 for nic in spec['nics']:
  subnet=nic['ip'].split('.')[2];end='r' if role=='runner' else 't'
  i=ET.SubElement(devices,'interface',{'type':'network'});ET.SubElement(i,'mac',{'address':nic['mac']});ET.SubElement(i,'source',{'network':nic['network']});ET.SubElement(i,'target',{'dev':'adr'+subnet+end});ET.SubElement(i,'model',{'type':'virtio'})
 ET.SubElement(devices,'controller',{'type':'virtio-serial','index':'0'})
 ch=ET.SubElement(devices,'channel',{'type':'unix'});ET.SubElement(ch,'target',{'type':'virtio','name':'org.qemu.guest_agent.0'})
 serial=ET.SubElement(devices,'serial',{'type':'pty'});ET.SubElement(serial,'target',{'port':'0'});ET.SubElement(serial,'log',{'file':str(STORE/(role+'-serial.log')),'append':'on'})
 video=ET.SubElement(devices,'video');ET.SubElement(video,'model',{'type':'vga','vram':'16384','heads':'1','primary':'yes'})
 ET.SubElement(devices,'memballoon',{'model':'none'})
 return ET.tostring(d,encoding='unicode')
def bridge_rules():
 ports=', '.join('"adr'+str(n)+end+'"' for n in [30,31,32] for end in ['r','t'])
 lines=[f'table bridge {TABLE} {{',f'chain input {{ type filter hook input priority -200; policy accept; iifname {{ {ports} }} counter drop; }}',f'chain output {{ type filter hook output priority -200; policy accept; oifname {{ {ports} }} counter drop; }}',f'chain forward {{ type filter hook forward priority 0; policy accept; iifname {{ {ports} }} jump scoped; oifname {{ {ports} }} jump scoped; }}','chain scoped {']
 for n,p in [(30,'22'),(31,'21, 50000-50009'),(32,'445')]:
  for src,dst,se,de in [(1,2,'r','t'),(2,1,'t','r')]:
   sm=f'52:54:00:ad:{n}:0{src}';dm=f'52:54:00:ad:{n}:0{dst}'
   prefix=f'iifname "adr{n}{se}" oifname "adr{n}{de}" ether saddr {sm}'
   lines.append(prefix+f' ether daddr {{ {dm}, ff:ff:ff:ff:ff:ff }} ether type arp arp operation {{ request, reply }} arp saddr ether {sm} arp saddr ip 10.203.{n}.{src} arp daddr ip 10.203.{n}.{dst} counter accept;')
   state='{ new, established }' if src==1 else 'established';field='dport' if src==1 else 'sport'
   lines.append(prefix+f' ether daddr {dm} ether type ip ip saddr 10.203.{n}.{src} ip daddr 10.203.{n}.{dst} tcp {field} {{ {p} }} ct state {state} counter accept;')
 lines+=['counter drop;','}','}'];return '\n'.join(lines)+'\n'
def guest_args(code,*args):return {'path':'/usr/bin/python3','arg':['-c',code,*args],'capture-output':True}

def docker_subnets(net):
 require(isinstance(net,dict),'Registro Docker no es objeto')
 driver=net.get('Driver');ipam=net.get('IPAM')
 require(isinstance(ipam,dict),'Docker IPAM no es objeto')
 require('Config' in ipam,'Docker IPAM sin campo Config')
 configs=ipam['Config']
 if configs is None or configs==[]:
  require(driver in ('host','null'),'Docker sin subred declarada requiere revisión: '+str(driver))
  return []
 require(isinstance(configs,list),'Docker IPAM.Config no es lista')
 subnets=[]
 for cfg in configs:
  require(isinstance(cfg,dict),'Configuración IPAM no es objeto')
  subnet=cfg.get('Subnet')
  require(isinstance(subnet,str) and bool(subnet),'Configuración IPAM sin subred válida')
  ipaddress.ip_network(subnet,strict=False)
  subnets.append(subnet)
 return subnets

PRIOR_STORE=Path('/var/lib/libvirt/images/ardrec-dev-point4-v4')
PRIOR_WORK=Path('/var/lib/ardrec-point4-activation-v4')
PRIOR_SHA='dc01531d5251a9a545a6c71ad82ab4f11b32c11b6cc6655ac0f0bbee04f35db1'
PROBE_WORK=Path('/var/lib/ardrec-point4-boot-probe-v2')
PROBE_SHA='2f6a60a53fd60b331afa72325b70d4bd26ac84840d1647b9ea7e0153250aaa9f'
BASE_HASHES={'ssh':'422aa101cc26463df4a9f651f9cc66ee3d646fd79fe1615a70de26e14efe0d62','ftp':'7c7992c4446c550c1b98da93ebfbe2b0d133cd14bf5eb4b7bf7818164e2cb974','smb':'ffeedf326e41f4679ae8cdb7a803a25f41671eaebcd7063740f40fd4584fa475','runner':'fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103'}

def pinned(path,digest,owner_uid=1000):
 regular(path,owner_uid)
 data=path.read_bytes();require(hashlib.sha256(data).hexdigest()==digest,'Evidencia distinta: '+str(path))
 return json.loads(data)

def validate_recovery(previous,probe,receipt):
 require(previous.get('base')==BASE and previous.get('script_sha256')=='70c17ee7ef5e0d36b87a46a1cfde8b08a08f6c384feb557f4cc057953ff21468','Procedencia de activación distinta')
 require(previous.get('status')=='INCOMPLETE_REVIEW_REQUIRED' and previous.get('guest_checks')=={},'Activación previa en otro estado')
 require(previous.get('all_created_domains_stopped') is True and previous.get('dedicated_firewall_removed') is True,'Limpieza previa no confirmada')
 require(not any('error' in x for x in previous['cleanup']),'Error de limpieza previo')
 require(probe.get('script_sha256')=='bedfebd59a98b45f24e8b17014625648360353b49f266cb403eabe2fd8976299' and probe.get('source_receipt_sha256')==PRIOR_SHA,'Procedencia de prueba distinta')
 require(probe.get('all_domains_inactive') is True and probe.get('original_disk_unchanged') is True and probe.get('original_disk_sha256')==BASE_HASHES['ssh'],'Prueba no confirma conservación/apagado')
 require(probe.get('service_activation')=='NOT_PERFORMED' and probe.get('network_changes')=='NONE' and probe.get('firewall_changes')=='NONE','Alcance de prueba distinto')
 require(set(probe['trials'])=={'control','vga'},'Comparación incompleta')
 control=probe['trials']['control'];vga=probe['trials']['vga']
 require(control.get('boot')=='DOMAIN_STOPPED_BEFORE_AGENT' and control.get('video')=='none' and control['cleanup'].get('stopped') is True,'Control distinto')
 require(vga.get('boot')=='GUEST_VERIFIED' and vga.get('video')=='vga' and vga['cleanup'].get('stopped') is True and vga['cleanup'].get('forced') is False,'VGA/apagado no verificado')
 require(vga.get('guest')=={'boot':'PASS_GUEST_AGENT_AND_IDENTITY','configuration':'UNCHANGED','kernel':'6.12.113+deb13-amd64','nics':'NONE','service_masks':'PRESERVED'},'Auditoría de huésped distinta')
 for trial in [control,vga]:
  require(trial['nics']==0 and trial['ram_mib']==768 and trial['vcpus']==1 and trial['cpu']=='host-model','Variables de comparación distintas')
  access=trial['qemu_access'];require(access['uid']==64055 and access['gid']==64055 and access['bytes_written']==0,'Acceso QEMU previo distinto')
 require(set(previous['domains'])==set(BASE_HASHES)==set(receipt['roles'])==set(previous['boot_repairs']),'Roles incompletos')
 for role,digest in BASE_HASHES.items():
  require(previous['domains'][role]['base_copy_sha256']==digest,'Base reparada distinta: '+role)
  repair=previous['boot_repairs'][role]
  require(repair['role']==role and repair['machine_id']==receipt['roles'][role]['summary']['machine_id'] and repair['root_device']=='/dev/sda3' and repair['role_configuration']=='UNCHANGED','Reparación/identidad distinta: '+role)
  require(repair['status']=='OFFLINE_BOOT_REPAIRED_NOT_BOOT_VERIFIED','Estado de reparación distinto')
  require(all(re.fullmatch('[0-9a-f]{64}',repair[k]) for k in ['fstab_sha256','grub_cfg_sha256']),'Huellas de arranque inválidas')

def verify_previous_attempt(receipt):
 previous=pinned(LAB/'point4-activation-receipt-v4.json',PRIOR_SHA)
 pinned(PRIOR_WORK/'activation-receipt-private.json',PRIOR_SHA)
 probe=pinned(LAB/'point4-boot-probe-receipt-v2.json',PROBE_SHA)
 pinned(PROBE_WORK/'boot-probe-receipt-private.json',PROBE_SHA,owner_uid=0)
 validate_recovery(previous,probe,receipt)
 for name,item in previous['commands'].items():
  path=PRIOR_WORK/'logs'/(name+'.log');require(str(path)==item['log'],'Ruta de registro distinta')
  regular(path,0);require(sha(path)==item['sha256'],'Registro previo cambió: '+name)
 for name,item in probe['commands'].items():
  require(re.fullmatch(r'[A-Za-z0-9_-]+',name),'Nombre de registro inválido')
  path=PROBE_WORK/(name+'.log');regular(path,0);require(sha(path)==item['sha256'],'Registro de comparación cambió: '+name)
 for trial in probe['trials'].values():
  for field in ['events','serial']:
   path=Path(trial[field]['path'])
   parent=PROBE_WORK if field=='events' else Path('/var/lib/libvirt/images/ardrec-boot-probe-v2')
   require(path.parent==parent and not path.is_symlink(),'Ruta de evidencia inesperada')
   require(sha(path)==trial[field]['sha256'],'Evidencia de comparación cambió')
 q=pwd.getpwnam('libvirt-qemu');require(q.pw_uid==64055 and q.pw_gid==64055,'Identidad QEMU distinta de la prueba')
 require(not any(p.is_symlink() for p in [PRIOR_STORE,*PRIOR_STORE.parents]),'Pool previo enlazado')
 st=PRIOR_STORE.stat();require(st.st_uid==0 and st.st_gid==q.pw_gid and stat.S_IMODE(st.st_mode) in (0o710,0o750),'Permisos de pool previo distintos')
 metadata={}
 for role,digest in BASE_HASHES.items():
  path=PRIOR_STORE/(role+'-base.qcow2');st=path.lstat()
  require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid in (0,q.pw_uid) and st.st_mode&0o222==0,'Base no regular/solo lectura: '+role)
  require(sha(path)==digest,'Base reutilizable cambió: '+role)
  metadata[role]={'path':str(path),'sha256':digest,'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode))}
 print('ARDREC_ACTIVATION_R8_PREFLIGHT=PINNED_VGA_COMPARISON_AND_FOUR_REPAIRED_BASES',flush=True)
 return {'previous_receipt_sha256':PRIOR_SHA,'boot_comparison_sha256':PROBE_SHA,'base_reuse':'NO_COPY_NO_REPAIR','previous_attempts':'PRESERVED','video':'VGA_16_MIB_NO_GRAPHICS_LISTENER','boot_repairs':previous['boot_repairs'],'bases':metadata}

FTP_PATCH="OLD_SHA='78dcb498b9bdf4cd5d678da7b8d024971e9f3e369eb80ed7cdd9ba4ff8ebf1fa'\nNEW_SHA='299faa64aaf4181053441d2de69999a8ef9f07e28c504cfcbaf36a7070cf1ac8'\nimport hashlib,json,os,re,stat,subprocess\nfrom pathlib import Path\n\ndef must(ok,message):\n if not ok:raise RuntimeError(message)\n\ndef patch_bytes(raw):\n must(hashlib.sha256(raw).hexdigest()==OLD_SHA,'FTP configuration differs from reviewed bytes')\n changes=[(b'ssl_tlsv1_1=NO\\n',b'ssl_tlsv11=NO\\n'),(b'ssl_tlsv1_2=YES\\n',b'ssl_tlsv12=YES\\n'),(b'ssl_tlsv1_3=YES\\n',b'ssl_tlsv13=YES\\n')]\n for old,new in changes:\n  must(raw.count(old)==1 and new not in raw,'Ambiguous FTP option')\n  raw=raw.replace(old,new)\n must(hashlib.sha256(raw).hexdigest()==NEW_SHA,'Unexpected patched digest')\n return raw\n\ndef main():\n must(Path('/etc/machine-id').read_text().strip()=='aab13c5edac949b4864e5c625f6c84b5','Wrong guest')\n unit=Path('/etc/systemd/system/vsftpd.service')\n must(unit.is_symlink() and os.readlink(unit)=='/dev/null','Service must still be masked')\n version=subprocess.run(['dpkg-query','-W','-f=${Version}','vsftpd'],capture_output=True,check=True,timeout=10).stdout.decode()\n must(version=='3.0.5-0.2','Unreviewed vsftpd version')\n binary=Path('/usr/sbin/vsftpd').read_bytes()\n strings=set(re.findall(rb'[ -~]{4,}',binary))\n for old,new in [('ssl_tlsv1_1','ssl_tlsv11'),('ssl_tlsv1_2','ssl_tlsv12'),('ssl_tlsv1_3','ssl_tlsv13')]:\n  must(old.encode() not in strings and new.encode() in strings,'Binary option names do not match reviewed parser')\n config=Path('/etc/vsftpd.conf');st=config.lstat()\n must(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1,'Unexpected config type/owner')\n raw=config.read_bytes();fixed=patch_bytes(raw)\n backup=Path('/etc/vsftpd.conf.ardrec-before-r8');tmp=Path('/etc/vsftpd.conf.ardrec-r8-new')\n for path,data in [(backup,raw),(tmp,fixed)]:\n  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,stat.S_IMODE(st.st_mode))\n  with os.fdopen(fd,'wb') as f:\n   os.fchown(f.fileno(),st.st_uid,st.st_gid);os.fchmod(f.fileno(),stat.S_IMODE(st.st_mode));f.write(data);f.flush();os.fsync(f.fileno())\n os.replace(tmp,config)\n fd=os.open('/etc',os.O_RDONLY|os.O_DIRECTORY)\n try:os.fsync(fd)\n finally:os.close(fd)\n must(config.read_bytes()==fixed and backup.read_bytes()==raw,'Config publication verification failed')\n print(json.dumps({'status':'THREE_TLS_OPTION_NAMES_CORRECTED','before_sha256':OLD_SHA,'after_sha256':NEW_SHA,'vsftpd_version':version,'binary_sha256':hashlib.sha256(binary).hexdigest(),'tls_policy':'TLS_1_2_AND_1_3_ONLY_UNCHANGED','scope':'NEW_RUNTIME_OVERLAY_ONLY','original_config_backup':str(backup),'source':'https://sources.debian.org/src/vsftpd/3.0.5-0.2/parseconf.c/'}))\n\nmain()\n"
FTP_CONFIG_SHA='299faa64aaf4181053441d2de69999a8ef9f07e28c504cfcbaf36a7070cf1ac8'

FTP_DIAGNOSTIC=LAB/'ftp-failure-read-l2ru0s2n/ftp-failure-report-private.json'
FTP_DIAGNOSTIC_SHA='c08f9f76e1dce42e8259caf984611bc416522d9fc806ab03694e93c971fc45d5'
R7_SHA='726ab15aa1639794b907572d3135fb23667427d33429ee20ee3293da14615cb9'
R7_FTP=Path('/var/lib/libvirt/images/ardrec-dev-point4-v5/ftp-runtime.qcow2')
R7_FTP_SHA='814530532a93181c9dbd16d08f20bfa8d6a826826858a78e07393d4fa2c457eb'
def validate_ftp_evidence(previous,diagnostic):
 require(previous.get('script_sha256')=='daedc71faaa0eb296edb7e4adf2fa61a37bfa12d2a11f98963760ee0a9ef14bf','Script de intento previo distinto')
 require(previous.get('base')==BASE and previous.get('status')=='INCOMPLETE_REVIEW_REQUIRED','Estado R7 distinto')
 for key in ['all_created_domains_stopped','dedicated_firewall_removed','created_networks_removed','reused_bases_unchanged']:
  require(previous.get(key) is True,'Limpieza R7 pendiente: '+key)
 require(not any('error' in x or x.get('forced_stop') for x in previous['cleanup']),'R7 necesita revisión de limpieza')
 require(diagnostic.get('activation_receipt_sha256')==R7_SHA and diagnostic.get('all_domains_inactive') is True and diagnostic.get('disks_unchanged') is True,'Lectura FTP distinta/incompleta')
 require(diagnostic.get('disk_sha256_before')==diagnostic.get('disk_sha256_after')==R7_FTP_SHA and diagnostic.get('base_sha256_after')==BASE_HASHES['ftp'],'Discos de diagnóstico distintos')
 for item in diagnostic['commands'].values():
  require(item['exit_code']==0 and hashlib.sha256(item['text'].encode()).hexdigest()==item['sha256'],'Registro FTP inválido')
 require(set(previous['guest_checks'])==set(EXPECTED),'Auditoría R7 incompleta')

def verify_ftp_evidence():
 previous=pinned(LAB/'point4-activation-receipt-v5.json',R7_SHA)
 pinned(Path('/var/lib/ardrec-point4-activation-v5/activation-receipt-private.json'),R7_SHA)
 diagnostic=pinned(FTP_DIAGNOSTIC,FTP_DIAGNOSTIC_SHA)
 validate_ftp_evidence(previous,diagnostic)
 st=R7_FTP.lstat();require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid in (0,64055) and not any(p.is_symlink() for p in [R7_FTP,*R7_FTP.parents]),'Overlay R7 inesperado')
 require(sha(R7_FTP)==R7_FTP_SHA,'Overlay FTP previo modificado')
 print('ARDREC_FTP_CORRECTION_PREFLIGHT=PINNED_DIAGNOSTIC_AND_CLEAN_R7',flush=True)
 return {'previous_attempt_sha256':R7_SHA,'diagnostic_sha256':FTP_DIAGNOSTIC_SHA,'previous_runtime_sha256':R7_FTP_SHA,'change':'THREE_OPTION_NAMES_ONLY_IN_NEW_FTP_OVERLAY'}

def prepare_pool(path,gid):
 private(path);os.chown(path,0,gid);path.chmod(0o750)
 st=path.stat();require(st.st_uid==0 and st.st_gid==gid and stat.S_IMODE(st.st_mode)==0o750,'Permisos de nuevo pool no confirmados')

ACCESS_CHECK="""import json,os,stat,sys
items=json.loads(sys.argv[1]);results=[]
for item in items:
 fd=os.open(item['path'],(os.O_RDWR if item['write'] else os.O_RDONLY)|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode):raise RuntimeError('Not regular')
  results.append({'path':item['path'],'access':'READ_WRITE_OPEN' if item['write'] else 'READ_OPEN'})
 finally:os.close(fd)
print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'checks':results,'bytes_written':0}))
"""

def verify_domain(live,role,spec,uid,disk):
 require(live.get('type')=='kvm' and live.findtext('uuid')==uid and live.findtext('name')=='ardrec-dev-'+role,'Identidad del dominio distinta')
 require(live.findtext('vcpu')==str(spec['vcpus']),'CPU distinta')
 memory=live.find('memory');unit=memory.get('unit','KiB');scale={'KiB':1,'MiB':1024,'k':1,'M':1024}.get(unit)
 require(scale is not None and int(memory.text)*scale==spec['ram_mib']*1024,'Memoria distinta')
 require(live.find('os/type').get('machine')=='pc-i440fx-11.1','Máquina distinta')
 videos=live.findall('devices/video/model')
 require(len(videos)==1 and videos[0].get('type')=='vga' and videos[0].get('vram')=='16384' and videos[0].get('heads')=='1','Adaptador VGA distinto')
 drives=live.findall('devices/disk')
 require(len(drives)==1 and drives[0].get('device')=='disk' and drives[0].find('source').get('file')==str(disk) and drives[0].find('driver').get('type')=='qcow2','Disco distinto')
 require(drives[0].find('target').get('bus')=='virtio','Bus de disco distinto')
 for tag in ['on_poweroff','on_reboot','on_crash']:require(live.findtext(tag)=='destroy','Política de ciclo de vida distinta')
 require(not any(live.findall('devices/'+tag) for tag in ['filesystem','hostdev','redirdev','graphics','vsock','smartcard']),'Dispositivo no autorizado')
 interfaces=live.findall('devices/interface');require(len(interfaces)==len(spec['nics']),'Número de NIC distinto')
 for i,nic in zip(interfaces,spec['nics']):
  tap='adr'+nic['ip'].split('.')[2]+('r' if role=='runner' else 't')
  require(i.get('type')=='network' and i.find('source').get('network')==nic['network'] and i.find('mac').get('address')==nic['mac'] and i.find('target').get('dev')==tap and i.find('model').get('type')=='virtio','NIC distinta')
 serials=live.findall('devices/serial');require(len(serials)==1 and serials[0].get('type')=='pty' and serials[0].find('log').get('file')==str(STORE/(role+'-serial.log')),'Consola distinta')
 channels=live.findall('devices/channel');require(len(channels)==1 and channels[0].get('type')=='unix' and channels[0].find('target').get('name')=='org.qemu.guest_agent.0','Canal de agente distinto')

def main():
 require(os.geteuid()==0 and os.environ.get('SUDO_USER')=='cicada' and os.environ.get('SUDO_UID')=='1000','Ejecutar con sudo desde cicada')
 require(len(sys.argv)==1 and not sys.flags.optimize,'No se admiten argumentos ni Python optimizado')
 os.umask(0o077);owner=pwd.getpwnam('cicada');require(owner.pw_uid==1000,'UID distinto')
 needed=['virsh','qemu-img','nft','iptables-nft','iptables-nft-save','iptables-legacy-save','ip6tables-legacy-save','ip','runuser','nmcli']
 bins={n:shutil.which(n,path=ENV['PATH']) for n in needed};require(all(bins.values()),'Herramientas ausentes: '+','.join(n for n in needed if not bins[n]))
 # Fixed, authenticated data only; no import of user-owned Python under root.
 receipt_path=BUILD/'role-build-receipt-private.json';regular(receipt_path,1000);require(sha(receipt_path)==RECEIPT_SHA,'Recibo distinto')
 receipt=json.loads(receipt_path.read_text());require(receipt['status']=='FOUR_ROLE_IMAGES_CONFIGURED_OFFLINE' and receipt['base']==BASE,'Base distinta')
 for role,entry in EXPECTED.items():
  item=receipt['roles'][role];require(item['image_sha256']==entry['image_sha256'] and item['resources']==entry['resources'],'Rol distinto')
  path=Path(item['image']);require(path==BUILD/'images'/('ardrec-dev-'+role+'.qcow2'),'Ruta de imagen distinta');regular(path,1000)
  require(path.stat().st_mode&0o222==0 and sha(path)==entry['image_sha256'],'Imagen modificada: '+role)
 for path in [STORE,WORK]:require(not path.exists() and not path.is_symlink(),'Ya existe '+str(path)+'; conservar y revisar')
 require(STORE.parent.is_dir() and not any(p.is_symlink() for p in [STORE.parent,*STORE.parent.parents]),'Pool libvirt no disponible')
 # root-owned lock prevents concurrent activation; no existing lab lock is replaced.
 lock=os.open('/run/ardrec-point4-activation.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);st=os.fstat(lock)
 require(st.st_uid==0 and st.st_nlink==1 and stat.S_ISREG(st.st_mode),'Lock inesperado');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 recovery=verify_previous_attempt(receipt)
 ftp_recovery=verify_ftp_evidence()
 private(WORK);private(WORK/'logs')
 report={'status':'IN_PROGRESS','base':BASE,'role_receipt_sha256':RECEIPT_SHA,'script_sha256':sha(Path(__file__).resolve()),'operator':'cicada','scope':'DEVELOPMENT_SERVICE_SMOKE_ONLY','commands':{},'guest_checks':{},'cleanup':[],'domains':{},'networks':{},'experimental_validation':'NOT_RUN','point_4':'IN_PROGRESS','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 report['ftp_recovery']=ftp_recovery
 report['recovery']=recovery;report['boot_repairs']=recovery['boot_repairs'];report['serial_consoles']={};report['qemu_access']={}
 domains=[];networks=[];hooks=[];chain_created=False;table_created=False;cleanup_phase=False;seq=0
 def resources(start=False):
  mem={s.split(':',1)[0]:int(s.split()[1]) for s in Path('/proc/meminfo').read_text().splitlines()}
  require(mem['MemAvailable']>=(7680 if start else 2048)*1024,'RAM disponible insuficiente')
  require(mem['MemTotal']>=(6144+5120)*1024,'RAM total insuficiente')
  require(shutil.disk_usage(LAB).free>=40*1024**3 and shutil.disk_usage(STORE.parent).free>=40*1024**3,'Reserva de disco inferior a 40 GiB')
  require(allocated(LAB)+sum(allocated(Path('/var/lib/libvirt/images')/('ardrec-dev-point4-v'+str(v)))+allocated(Path('/var/lib')/('ardrec-point4-activation-v'+str(v))) for v in [1,2,3,4,5,6])+sum(allocated(Path('/var/lib/libvirt/images')/('ardrec-boot-probe-v'+str(v)))+allocated(Path('/var/lib')/('ardrec-point4-boot-probe-v'+str(v))) for v in [1,2])<=80*1024**3,'Presupuesto de laboratorio superior a 80 GiB')
  for role in EXPECTED:
   serial=STORE/(role+'-serial.log')
   require(not serial.exists() or serial.stat().st_size<8*1024**2,'Consola excede 8 MiB: '+role)
 def run(label,args,check=True,timeout=90,input=None,identity=None):
  nonlocal seq
  seq+=1;name=f'{seq:03d}-{label}';log=WORK/'logs'/(name+'.log')
  if not cleanup_phase:resources()
  print('ARDREC_ACTIVATION_COMMAND='+label+':START',flush=True)
  with log.open('xb') as out:
   p=subprocess.Popen([str(a) for a in args],stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,env=ENV,start_new_session=True,**({'user':identity[0],'group':identity[1],'extra_groups':[]} if identity else {}))
   try:
    if input is not None:p.stdin.write(input);p.stdin.close()
    start=time.monotonic()
    while p.poll() is None:
     if not cleanup_phase:resources()
     require(time.monotonic()-start<timeout,'Timeout: '+label);require(log.stat().st_size<8*1024**2,'Salida excesiva: '+label)
     try:p.wait(timeout=5)
     except subprocess.TimeoutExpired:print('ARDREC_ACTIVATION_WAIT='+label,flush=True)
   except BaseException:
    if p.poll() is None:os.killpg(p.pid,signal.SIGKILL);p.wait()
    raise
   finally:report['commands'][name]={'exit_code':p.returncode,'log':str(log),'sha256':sha(log)}
  text=log.read_text(errors='replace')
  require(not check or p.returncode==0,label+' falló; revisar '+str(log))
  print('ARDREC_ACTIVATION_COMMAND='+label+':'+('PASS' if p.returncode==0 else 'NONZERO'),flush=True)
  return p.returncode,text
 def vir(label,*args,**kw):return run(label,[bins['virsh'],'--connect','qemu:///system',*args],**kw)
 def git_state():
  r={}
  for key,args in [('head',['rev-parse','HEAD']),('main',['rev-parse','main']),('origin',['rev-parse','origin/main']),('branch',['branch','--show-current']),('worktree',['status','--porcelain=v1','--untracked-files=all'])]:
   r[key]=run('git-'+key,[bins['runuser'],'-u','cicada','--','git','-C',REPO,*args])[1].strip()
  require(all(r[k]==BASE for k in ['head','main','origin']) and r['branch']=='main' and not r['worktree'],'Estado Git distinto');return r
 def ga(role,request,check=True):
  code,text=vir('agent-'+role,'qemu-agent-command',report['domains'][role]['uuid'],'--timeout','10',json.dumps(request,separators=(',',':')),check=check,timeout=20)
  if code:return None
  d=json.loads(text);require('error' not in d,'Error QGA: '+str(d.get('error')));return d['return']
 def guest(role,label,code,*args,timeout=180):
  launch=ga(role,{'execute':'guest-exec','arguments':guest_args(code,*args)});pid=launch['pid'];deadline=time.monotonic()+timeout
  while True:
   r=ga(role,{'execute':'guest-exec-status','arguments':{'pid':pid}})
   if r.get('exited'):break
   require(time.monotonic()<deadline,'Timeout invitado '+role+'/'+label);time.sleep(2)
  require(not r.get('out-truncated') and not r.get('err-truncated'),'Salida invitado truncada')
  out=base64.b64decode(r.get('out-data','')).decode(errors='replace');err=base64.b64decode(r.get('err-data','')).decode(errors='replace')
  write(WORK/'logs'/(role+'-'+label+'.json'),json.dumps(r,sort_keys=True,indent=2)+'\n')
  require(r.get('exitcode')==0,role+'/'+label+' falló: '+err[-2000:])
  return json.loads(out)
 def verify_bridges():
  links=json.loads(run('links',['ip','-j','-d','link','show'])[1]);addrs=json.loads(run('addresses',['ip','-j','address','show'])[1]);byname={x['ifname']:x for x in links}
  for role,n in [('ssh',30),('ftp',31),('smb',32)]:
   bridge='brad'+str(n);require(bridge in byname,'Puente ausente')
   require(byname[bridge].get('linkinfo',{}).get('info_kind')=='bridge','Interfaz no es bridge')
   require(not next(x for x in addrs if x['ifname']==bridge)['addr_info'],'Puente con IP')
   ports={x['ifname'] for x in links if x.get('master')==bridge or x.get('master')==byname[bridge]['ifindex']}
   require(ports<= {'adr'+str(n)+'r','adr'+str(n)+'t'},'Puerto ajeno en puente')
  return True
 try:
  resources(start=True);before=git_state()
  capabilities=ET.fromstring(vir('domain-capabilities','domcapabilities','--virttype','kvm','--arch','x86_64','--machine','pc-i440fx-11.1')[1]);require(capabilities.findtext('domain')=='kvm','KVM no confirmado')
  require('vga' in [x.text for x in capabilities.findall("devices/video/enum[@name='modelType']/value")],'VGA no disponible')
  known_domains=vir('domain-inventory','list','--all','--name')[1].splitlines();known_nets=vir('network-inventory','net-list','--all','--name')[1].splitlines()
  require(not any(n.startswith('ardrec-') for n in known_domains+known_nets),'Recursos ARDREC existentes')
  links=json.loads(run('links-before',['ip','-j','link','show'])[1]);require(not any(x['ifname'].startswith(('adr30','adr31','adr32','brad30','brad31','brad32')) for x in links),'Interfaces reservadas existentes')
  reserved=[ipaddress.ip_network(f'10.203.{n}.0/28') for n in [30,31,32]]
  def overlap(cidr):
   network=ipaddress.ip_network(cidr,strict=False);return network.version==4 and any(network.overlaps(x) for x in reserved)
  for family in ['-4','-6']:
   rows=json.loads(run('routes'+family,['ip',family,'-j','route','show','table','all'])[1])
   for row in rows:
    dst=row.get('dst','default')
    if dst!='default':require(not overlap(dst),'Ruta superpuesta: '+dst)
  run('policy-routes',['ip','rule','show'])
  for name in known_nets:
   if not name.strip():continue
   xml=ET.fromstring(vir('existing-network','net-dumpxml',name)[1])
   for ip in xml.findall('ip'):
    address=ip.get('address');prefix=ip.get('prefix') or ip.get('netmask')
    if address and prefix:require(not overlap(address+'/'+prefix),'Red libvirt superpuesta')
  docker=shutil.which('docker',path=ENV['PATH'])
  if docker:
   ids=run('docker-networks',[docker,'network','ls','-q'])[1].split()
   if ids:
    docker_data=json.loads(run('docker-ipam',[docker,'network','inspect',*ids])[1])
    require(isinstance(docker_data,list),'Inventario Docker no es lista')
    for net in docker_data:
     for subnet in docker_subnets(net):require(not overlap(subnet),'Docker superpuesto: '+subnet)
  profiles=run('nm-profiles',[bins['nmcli'],'-t','-f','UUID','connection','show'])[1].splitlines()
  for profile in profiles:
   if not profile:continue
   text=run('nm-profile-addresses',[bins['nmcli'],'-g','ipv4.addresses,ipv4.routes','connection','show',profile])[1]
   for cidr in re.findall(r'\b\d+\.\d+\.\d+\.\d+/\d+\b',text):require(not overlap(cidr),'Perfil NetworkManager superpuesto')
  # Inactive VPNs with dynamic remote addresses are recorded, not claimed fully known.
  report['vpn_inventory_scope']='LOCAL_CONFIGURED_PREFIXES_ONLY_NO_EXTERNAL_TRAFFIC'
  run('firewall-before',[bins['nft'],'-j','list','ruleset'])
  tables=json.loads(run('nft-tables',[bins['nft'],'-j','list','tables'])[1]);require(not any(x.get('table',{}).get('name')==TABLE for x in tables['nftables']),'Tabla ARDREC existente')
  ipt_before=run('iptables-before',[bins['iptables-nft-save']])[1];require(CHAIN not in ipt_before,'Cadena ARDREC existente')
  # Legacy forwarding chains must not unexpectedly conflict with nft's path.
  for binname in ['iptables-legacy-save','ip6tables-legacy-save']:
   text=run(binname,[bins[binname]])[1]
   require(not re.search(r'^:FORWARD (DROP|REJECT)',text,re.M) and not re.search(r'^-A FORWARD ',text,re.M),'Firewall legacy FORWARD requiere revisión')
  # Standard distro QEMU user; custom qemu.conf ownership is refused, not guessed.
  conf=Path('/etc/libvirt/qemu.conf').read_text() if Path('/etc/libvirt/qemu.conf').exists() else ''
  q=pwd.getpwnam('libvirt-qemu');group=grp.getgrgid(q.pw_gid).gr_name
  for key,value in re.findall(r'^\s*(user|group|dynamic_ownership)\s*=\s*([^#\n]+)',conf,re.M):
   parsed=ast.literal_eval(value.strip())
   allowed={'user':{'libvirt-qemu','+'+str(q.pw_uid)},'group':{group,'+'+str(q.pw_gid)},'dynamic_ownership':{1}}[key]
   require(parsed in allowed,'Propietario QEMU personalizado requiere revisión')
  prepare_pool(STORE,q.pw_gid)
  # Reuse the four repaired, hash-pinned bases read-only. Only overlays are new.
  for role,item in receipt['roles'].items():
   template=PRIOR_STORE/(role+'-base.qcow2');runtime=STORE/(role+'-runtime.qcow2')
   info=json.loads(run('base-info-'+role,[bins['qemu-img'],'info','--output=json','-f','qcow2',template])[1])
   require(info.get('format')=='qcow2' and not info.get('backing-filename') and info.get('virtual-size')==EXPECTED[role]['resources']['disk_gib']*1024**3,'Base QCOW2 distinta: '+role)
   serial=STORE/(role+'-serial.log');write(serial,b'');os.chown(serial,q.pw_uid,q.pw_gid);serial.chmod(0o600)
   run('overlay-'+role,[bins['qemu-img'],'create','-f','qcow2','-F','qcow2','-b',template,runtime]);os.chown(runtime,q.pw_uid,q.pw_gid);runtime.chmod(0o600)
   items=[{'path':str(template),'write':False},{'path':str(runtime),'write':True},{'path':str(serial),'write':True}]
   access=json.loads(run('qemu-access-'+role,['/usr/bin/python3','-I','-c',ACCESS_CHECK,json.dumps(items)],identity=(q.pw_uid,q.pw_gid))[1])
   require(access['uid']==q.pw_uid and access['gid']==q.pw_gid and access['groups']==[] and access['bytes_written']==0,'Credenciales de acceso QEMU distintas')
   report['qemu_access'][role]=access
   print('ARDREC_QEMU_FILE_ACCESS='+role+':PASS',flush=True)
   report['domains'][role]={'uuid':str(uuid.uuid4()),'name':'ardrec-dev-'+role,'base_path':str(template),'base_copy_sha256':BASE_HASHES[role],'runtime':str(runtime),'video':'vga'}
  print('ARDREC_ACTIVATION_BASES=FOUR_REUSED_NO_COPY_NO_REPAIR',flush=True)
  policy=WORK/'bridge.nft';write(policy,bridge_rules());run('bridge-policy-syntax',[bins['nft'],'--check','--file',policy])
  # Install only our own table and own scoped compatibility chain.
  run('bridge-policy-install',[bins['nft'],'--file',policy]);table_created=True
  run('compat-chain-create',[bins['iptables-nft'],'-w','5','-N',CHAIN]);chain_created=True
  for n,ports in [(30,'22'),(31,'21,50000:50009'),(32,'445')]:
   for src,dst,se,de in [(1,2,'r','t'),(2,1,'t','r')]:
    rule=['-m','physdev','--physdev-is-bridged','--physdev-in',f'adr{n}{se}','--physdev-out',f'adr{n}{de}','-s',f'10.203.{n}.{src}','-d',f'10.203.{n}.{dst}','-p','tcp','-m','multiport','--dports' if src==1 else '--sports',ports,'-m','conntrack','--ctstate','NEW,ESTABLISHED' if src==1 else 'ESTABLISHED','-j','ACCEPT']
    run('compat-allow',[bins['iptables-nft'],'-w','5','-A',CHAIN,*rule])
  run('compat-return',[bins['iptables-nft'],'-w','5','-A',CHAIN,'-j','RETURN'])
  for n in [30,31,32]:
   for end in ['r','t']:
    rule=['-m','physdev','--physdev-is-bridged','--physdev-in',f'adr{n}{end}','-j',CHAIN]
    run('compat-hook',[bins['iptables-nft'],'-w','5','-I','FORWARD','1',*rule]);hooks.append(rule)
  for role,n in [('ssh',30),('ftp',31),('smb',32)]:
   uid=str(uuid.uuid4());xml=WORK/(role+'-network.xml');write(xml,network_xml(role,uid))
   networks.append(uid);report['networks'][role]={'uuid':uid,'bridge':'brad'+str(n)}
   vir('network-create-'+role,'net-create',xml,'--validate')
   sysctl=Path('/proc/sys/net/ipv6/conf')/('brad'+str(n))/'disable_ipv6';sysctl.write_text('1\n')
  verify_bridges();resources(start=True)
  for role in ['ssh','ftp','smb','runner']:
   entry=report['domains'][role];xml=WORK/(role+'-domain.xml');write(xml,domain_xml(role,receipt['roles'][role]['resources'],entry['uuid'],entry['runtime']))
   domains.append(entry['uuid'])
   vir('domain-create-'+role,'create',xml,'--paused','--validate')
   live=ET.fromstring(vir('domain-xml-'+role,'dumpxml',entry['uuid'])[1])
   verify_domain(live,role,receipt['roles'][role]['resources'],entry['uuid'],entry['runtime'])
  verify_bridges()
  report['authorization']={'basis':'USER_REQUEST_POINT4_IMPLEMENTATION','operator_uid':1000,'environment':'dev','targets':report['domains'],'allowed_actions':['service_start','synthetic_authentication','known_fixture_read','new_temporary_marker_write_read_delete'],'excluded':['external_traffic','vulnerability_exploitation','experiment','ARDREC_algorithms'],'execution_concurrency':1}
  write(WORK/'authorization.json',json.dumps(report['authorization'],sort_keys=True,indent=2)+'\n')
  for role in ['ssh','ftp','smb','runner']:vir('resume-'+role,'resume',report['domains'][role]['uuid'])
  for role in ['ssh','ftp','smb','runner']:
   deadline=time.monotonic()+150
   while True:
    active=vir('boot-active-'+role,'list','--uuid')[1].split()
    require(report['domains'][role]['uuid'] in active,'VM terminó durante el arranque: '+role+'; consola conservada en el recibo')
    if ga(role,{'execute':'guest-ping'},check=False) is not None:break
    require(time.monotonic()<deadline,'Guest agent no disponible: '+role);time.sleep(3)
   expected=dict(receipt['roles'][role]['summary']);expected['package_versions']=receipt['package_versions'];report['guest_checks'][role]=guest(role,'audit',AUDIT,json.dumps(expected))
   require(abs(report['guest_checks'][role]['utc_ns']-time.time_ns())<30*10**9,'Desviación UTC superior a 30 segundos')
   boot_audit="import hashlib,json;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in ['/etc/fstab','/boot/grub/grub.cfg']}))"
   actual=guest(role,'boot-files-audit',boot_audit);repair=report['boot_repairs'][role]
   require(actual=={'/etc/fstab':repair['fstab_sha256'],'/boot/grub/grub.cfg':repair['grub_cfg_sha256']},'Archivos de arranque cambiaron: '+role)
   report['guest_checks'][role]['boot_files']='VERIFIED_AFTER_BOOT'
  verify_bridges()
  report['ftp_configuration_correction']=guest('ftp','configuration-correction',FTP_PATCH)
  require(report['ftp_configuration_correction']['status']=='THREE_TLS_OPTION_NAMES_CORRECTED' and report['ftp_configuration_correction']['after_sha256']==FTP_CONFIG_SHA,'Corrección FTP no confirmada')
  expected=json.loads(json.dumps(receipt['roles']['ftp']['summary']));expected['package_versions']=receipt['package_versions'];expected['config_sha256']['/etc/vsftpd.conf']=FTP_CONFIG_SHA
  report['guest_checks']['ftp']['corrected_audit']=guest('ftp','corrected-audit',AUDIT,json.dumps(expected))
  for role in ['ftp','ssh','smb']:
   activation=guest(role,'service-start',START,role);report['guest_checks'][role]['activation']=activation
   require(activation['status']=='READY_STABLE_LISTENER','Servicio no listo: '+role+'; diagnóstico incluido en recibo')
  report['smoke']=guest('runner','smoke',SMOKE,timeout=600)
  require(report['smoke']['status']=='DEVELOPMENT_SMOKE_PASS','Smoke incompleto: '+report['smoke'].get('error','sin detalle'))
  for role in ['ssh','ftp','smb']:
   code="import json;from pathlib import Path;p=Path('/srv/ardrec/"+role+"/temporary');n=[x.name for x in p.iterdir()];assert not n,n;print(json.dumps({'temporary_directory':'EMPTY'}))"
   report['guest_checks'][role]['marker_cleanup']=guest(role,'marker-cleanup',code)
  config_check="import hashlib,json;from pathlib import Path;print(json.dumps({'sha256':hashlib.sha256(Path('/etc/vsftpd.conf').read_bytes()).hexdigest()}))"
  report['ftp_final_config']=guest('ftp','final-config',config_check)
  require(report['ftp_final_config']['sha256']==FTP_CONFIG_SHA,'Configuración FTP cambió durante pruebas')
  require(git_state()==before,'Git cambió')
  for role,item in receipt['roles'].items():require(sha(Path(item['image']))==item['image_sha256'],'Imagen original cambió')
  for role,digest in BASE_HASHES.items():require(sha(PRIOR_STORE/(role+'-base.qcow2'))==digest,'Base reutilizada cambió: '+role)
  report['reused_bases_unchanged']=True
  report['status']='SERVICE_SMOKE_PASSED_PENDING_SHUTDOWN'
 except BaseException as error:
  report['error']=str(error)
  for role in ['ftp','ssh','smb']:
   if role not in report['guest_checks']:continue
   unit={'ssh':'ssh.service','ftp':'vsftpd.service','smb':'smbd.service'}[role]
   code="import json,subprocess,sys;p=subprocess.run(['journalctl','-b','-u',sys.argv[1],'--no-pager','-n','60'],capture_output=True,timeout=15);print(json.dumps({'exit_code':p.returncode,'journal':(p.stdout+p.stderr).decode(errors='replace')[-16000:]}))"
   try:report['guest_checks'][role]['failure_journal']=guest(role,'failure-journal',code,unit,timeout=30)
   except Exception as diagnostic_error:report['guest_checks'][role]['failure_journal_error']=str(diagnostic_error)
  raise
 finally:
  cleanup_phase=True
  signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN)
  # Stop only UUIDs created by this invocation, preserving disks and all logs.
  for uid in reversed(domains):
   try:
    vir('shutdown','shutdown',uid,check=False)
    deadline=time.monotonic()+45
    while True:
     rc,text=vir('shutdown-state','domstate',uid,check=False)
     if rc or text.strip()=='shut off':break
     if time.monotonic()>deadline:
      vir('forced-stop','destroy',uid);report['cleanup'].append({'uuid':uid,'forced_stop':True});break
     time.sleep(3)
    report['cleanup'].append({'uuid':uid,'stopped':True})
   except Exception as e:report['cleanup'].append({'uuid':uid,'error':str(e)})
  safe=False
  try:
   inventory_rc,inventory_text=vir('final-domain-inventory','list','--uuid',check=False)
   active=inventory_text.split()
   safe=inventory_rc==0 and not any(uid in active for uid in domains)
  except Exception as e:report['cleanup'].append({'error':'No se pudo confirmar el apagado: '+str(e)})
  report['all_created_domains_stopped']=safe
  if safe:
   for uid in reversed(networks):
    try:vir('network-stop','net-destroy',uid);report['cleanup'].append({'network':uid,'stopped':True})
    except Exception as e:report['cleanup'].append({'network':uid,'error':str(e)})
   for rule in reversed(hooks):
    try:run('compat-unhook',[bins['iptables-nft'],'-w','5','-D','FORWARD',*rule])
    except Exception as e:report['cleanup'].append({'error':str(e)})
   if chain_created:
    try:
     run('compat-chain-clear',[bins['iptables-nft'],'-w','5','-F',CHAIN]);run('compat-chain-delete',[bins['iptables-nft'],'-w','5','-X',CHAIN])
    except Exception as e:report['cleanup'].append({'error':str(e)})
   if table_created:
    try:run('bridge-policy-remove',[bins['nft'],'delete','table','bridge',TABLE])
    except Exception as e:report['cleanup'].append({'error':str(e)})
  else:report['cleanup'].append({'error':'VM sigue activa: se conserva el filtrado; no iniciar otra ejecución'})
  try:
   netrc,nettext=vir('final-network-inventory','net-list','--uuid',check=False)
   require(netrc==0 and not set(networks).intersection(nettext.split()),'Redes temporales siguen activas')
   final_links=json.loads(run('final-links',['ip','-j','link','show'])[1])
   require(not any(x['ifname'] in {'brad30','brad31','brad32','adr30r','adr30t','adr31r','adr31t','adr32r','adr32t'} for x in final_links),'Interfaces temporales siguen presentes')
   report['created_networks_removed']=True
  except Exception as e:
   report['created_networks_removed']=False;report['cleanup'].append({'error':str(e)})
  try:
   after=run('iptables-after',[bins['iptables-nft-save']])[1]
   remaining=json.loads(run('nft-tables-after',[bins['nft'],'-j','list','tables'])[1])
   report['dedicated_firewall_removed']=CHAIN not in after and not any(x.get('table',{}).get('name')==TABLE for x in remaining['nftables'])
   if not report['dedicated_firewall_removed']:report['cleanup'].append({'error':'Persisten reglas temporales ARDREC'})
   run('firewall-after',[bins['nft'],'-j','list','ruleset'])
  except Exception as e:report['cleanup'].append({'error':str(e)})
  try:
   report['previous_ftp_runtime_unchanged']=sha(R7_FTP)==R7_FTP_SHA
   require(report['previous_ftp_runtime_unchanged'],'Overlay FTP previo cambió')
   report['reused_bases_unchanged']=all(sha(PRIOR_STORE/(role+'-base.qcow2'))==digest for role,digest in BASE_HASHES.items())
   require(report['reused_bases_unchanged'],'Cambió una base reutilizada')
  except Exception as e:report['cleanup'].append({'error':str(e)})
  if report['status']=='SERVICE_SMOKE_PASSED_PENDING_SHUTDOWN' and safe and not any('error' in x or x.get('forced_stop') for x in report['cleanup']):report['status']='DEVELOPMENT_SERVICES_SMOKE_VERIFIED_STOPPED'
  else:report['status']='INCOMPLETE_REVIEW_REQUIRED'
  for role in EXPECTED:
   serial=STORE/(role+'-serial.log')
   if serial.exists():
    try:
     with serial.open('rb') as stream:
      stream.seek(max(0,serial.stat().st_size-32768));tail=stream.read(32768)
     report['serial_consoles'][role]={'path':str(serial),'bytes':serial.stat().st_size,'sha256':sha(serial),'tail':tail.decode(errors='replace')}
    except Exception as e:report['serial_consoles'][role]={'error':str(e)}
  out=WORK/'activation-receipt-private.json';write(out,json.dumps(report,sort_keys=True,indent=2)+'\n');os.chown(out,1000,owner.pw_gid)
  # Export the bounded receipt to a newly created operator-private directory.
  export=LAB/'point4-activation-receipt-v6.json'
  try:
   require(not export.exists() and not export.is_symlink(),'Recibo de exportación ya existe')
   write(export,out.read_bytes());os.chown(export,1000,owner.pw_gid);print('ARDREC_ACTIVATION_RECEIPT_PRIVATE='+str(export),flush=True)
  except Exception:print('ARDREC_ACTIVATION_RECEIPT_ROOT='+str(out),flush=True)
  print('ARDREC_ACTIVATION_RECEIPT_SHA256='+sha(out),flush=True);os.close(lock)
 require(report['status']=='DEVELOPMENT_SERVICES_SMOKE_VERIFIED_STOPPED','Activación incompleta; revisar recibo')
 print('ARDREC_SERVICE_SMOKE=PASS\nARDREC_VM_FINAL_STATE=STOPPED\nARDREC_POINT_4=IN_PROGRESS_PENDING_EVIDENCE_REVIEW_AND_DOCUMENTATION\nARDREC_EXPERIMENTAL_VALIDATION=NOT_RUN',flush=True)
if __name__=='__main__':
 def interrupted(signum,frame):raise KeyboardInterrupt('signal '+str(signum))
 signal.signal(signal.SIGTERM,interrupted)
 try:main()
 except (Exception,KeyboardInterrupt) as error:
  print('ARDREC_ACTIVATION=FAIL: '+json.dumps(str(error),ensure_ascii=True),flush=True)
  print('Conservar el estado y los registros; no repetir el bloque ni arrancar manualmente las VM.',flush=True)
  sys.exit(1)
