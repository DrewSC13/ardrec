"""R113-F4A. Clasificación conservadora de inventarios systemd recogidos localmente.

No infiere instalación de software ni escucha TCP de una unidad no observada.
"""
from __future__ import annotations
import re

SCHEMA='ardrec-r113-f4a-systemd-local-inventory-v1'
UNITS={
 'ftp':('vsftpd.service','proftpd.service','pure-ftpd.service'),
 'smb':('smbd.service','samba.service','samba-ad-dc.service','nmbd.service'),
}
CMDS={
 'unit-files':('/usr/bin/systemctl',('list-unit-files','--type=service','--no-legend','--no-pager','--plain')),
 'units':('/usr/bin/systemctl',('list-units','--all','--type=service','--no-legend','--no-pager','--plain')),
}

class GuardError(ValueError): pass

def need(value,why):
    if not value:raise GuardError(why)

def inventory(role:str, commands:dict[str, bytes])->dict:
    need(role in UNITS,'ROLE_NOT_ALLOWLISTED')
    need(type(commands) is dict and set(commands)==set(CMDS),'COMMAND_SCOPE_CHANGED')
    found={name:{} for name in UNITS[role]}
    for kind in ('unit-files','units'):
        data=commands[kind]
        need(type(data) is bytes and len(data)<=48000,'SYSTEMD_DATA_INVALID')
        try: source=data.decode('utf-8','strict')
        except UnicodeDecodeError as exc:raise GuardError('SYSTEMD_ENCODING_INVALID') from exc
        for row in source.splitlines():
            need(len(row)<=2048,'SYSTEMD_LINE_OVERSIZE')
            tokens=row.replace('●','').strip().split()
            # No se infiere nada de menciones dentro de una descripción de unidad.
            for unit in UNITS[role]:
                if tokens and tokens[0] == unit:
                    need(unit not in found or kind not in found[unit], 'DUPLICATE_UNIT_ROW')
                    found[unit][kind]=row.strip()
    return {
        'role':role,
        'unit_names_checked':list(UNITS[role]),
        'observed':{key:value for key,value in found.items() if value},
        'not_observed_in_systemctl':[key for key,value in found.items() if not value],
        'installation_proven':False,
        'services_started_by_audit':0,
        'protocol_connectivity_proven':False,
        'p8_operational':'NO-GO',
    }
