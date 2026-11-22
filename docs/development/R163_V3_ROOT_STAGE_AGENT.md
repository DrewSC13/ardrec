# ARDREC R163 V3 — Agente root de staging monousuario

## Naturaleza

El agente instala únicamente candidatos de fuente B4/B9 en
cuarentena, sin activar los ejecutores históricos.

Se construye un ZIP reproducible a partir de un commit firmado,
con manifiesto de identidad Git, UID del operador, hashes
de módulos y hashes de B4/B9.

El agente privilegiado solo puede ejecutarse desde:

`/opt/ardrec/r163-installer-v1/installer.py`

mediante Python aislado (`-I -B`), después del aprovisionamiento
externo de directorios root-owned y documentos firmados.

## Documentos requeridos

- `/etc/ardrec/r163-stage-trust-v1.json`
- `/etc/ardrec/r163-stage-authorization-v1.json`
- `/etc/ardrec/r163-stage-revocation-v1.json`

Todos deben estar protegidos contra escritura por usuarios
no privilegiados. La autorización y la revocación se validan
criptográficamente; su correspondencia con una persona
independiente NO se afirma.

## Operaciones

`--capabilities` consulta capacidades sin privilegios.

`--preflight` exige instalación externa y verifica autenticidad,
documentos y revocación, sin escritura de staging.

`--stage` exige la misma instalación y revisa la revocación
antes de journal, B4, B9 y recibo. Publica exclusivamente
fuentes candidatas bajo `/var/lib/ardrec`.

No se proporciona un comando de bootstrap root automático.
El aprovisionamiento exige revisión separada de identidad
de claves, permisos, hashes y firma del commit.

## Límites

El código B4/B9 V2 permanece inalterado. Los manifiestos F4
declaran expresamente que NO hubo instalación independiente.

No se habilitan ejecución FTP, red, libvirt, P7, P8, A6 ni A9.

Estado: AGENTE ROOT CANDIDATO / SIN INSTALACIÓN FÍSICA.
