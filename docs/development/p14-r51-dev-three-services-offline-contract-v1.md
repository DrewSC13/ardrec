# P14 R51 · Tres unidades DEV, auditoría offline y R34 / Three DEV units and R34 audit

## Español

**Objeto:** crear tres fichas de observación de desarrollo, una por SSH, FTPS y SMB/Samba, a partir de los datos ya registrados en `lab/services-v1` y `lab/topology-v1.json`. Mantener separadas identidad, configuración declarada, pruebas de humo históricas, estado efectivo actual y evidencia admisible por ARDREC.

**Fuentes:** tesis capítulo III, §3.6–3.8, tablas 3.9–3.11; P4 `lab/services-v1/config/{ssh,ftp,smb}.conf`, `resources.json`, `versions.json`, `evidence.json`; P6 `lab/scenario-separation-v1/registry.json`; P7 `lab/operational-catalog-v1/catalog.json`; R33–R50-A. La fuente del 4 de noviembre documenta 17 pruebas exitosas en su ventana histórica, no un PASS físico en la fecha actual.

El manifiesto `lab/p14-r51-dev-three-services-v1/manifest.json` registra **DEV-SSH-001**, **DEV-FTP-001** y **DEV-SMB-001**, con redes /28, roles, dominios, usuarios sintéticos, versiones y huellas de configuración provenientes de archivos versionados. Preserva intactos los manifiestos P6 y la muestra científica: no añade ninguna de las 54 unidades experimentales, no congela piloto/experimento y no llama «caso real ejecutado» a ninguna familia P7.

Cada una de las 25 familias está **PENDING** o **PARTIAL**. PARTIAL solo señala que existe alguna prueba de humo de desarrollo potencialmente relacionada, con nombre y recibo histórico. No demuestra todas las precondiciones, la clasificación A6, una ejecución completa del caso, un hallazgo de vulnerabilidad ni aceptación. No existe ninguna familia COVERED todavía. Un resultado positivo en un servicio no se transfiere a otro ni un silencio se convierte en negativo.

El verificador `lab/verify_p14_r51_dev_contract.py` falla ante divergencias de rol, topología, versiones, huellas de configuración, referencias, obligaciones o permisos de emisión de resultados. En particular, impide cambiar por accidente `P8=NO-GO`, `R34=NOT_VERIFIED`, `A6=sin admitir`, `A9=sin generación` y `Rf=null`. Es un ensayo de **consistencia de fuentes offline**, no una ejecución de VM ni un certificado de aislamiento.

`ardrec_p14_r51_host_audit.py` es una herramienta **optativa**, de solo lectura, que ejecuta exactamente cuatro consultas fijas `nft`/`virsh` con `sudo -n` (sin shell), escribe los resultados en un directorio privado 0700 y archivos 0600, y devuelve siempre **NO-GO**. La presencia de `bridge ardrec_r34_guard` no basta para demostrar la contención; ausencia o error también quedan registrados. No restaura nftables, no define/arranca máquinas o redes, no usa QGA y no consulta servicios. El operador revisa los resultados con la cadena de recibos y fuentes antes de cualquier plan de restauración separado.

La CI de Python incorpora el descubrimiento exigido de las **41 pruebas R50-A** y de **35 pruebas R51**, con fallo si descubre menos. Ni un CI verde ni una compilación autorizan acción física. El instalador se aplica en un worktree a partir de HEAD de PR #125 y valida el blob anterior del YAML de CI: evita sobrescribir trabajo del operador.

**Pruebas locales después de aplicar en el worktree:**

```bash
python3 -B lab/verify_p14_r51_dev_contract.py
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r50a*.py' -v
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r51*.py' -v
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14*.py' -q
python3 -B scripts/verificar_trazabilidad_actual.py
```

**Próxima acción con presencia del operador:** recopilar la inspección física privada y clasificar por separado estado actual de tabla R34, VMs, redes, nwfilter, NIC, IP y respaldo. Si R34 está ausente/no verificable, el laboratorio permanece apagado. Solo con decisión explícita y restauración controlada podrá aprobarse otro plan DEV para SSH y luego FTP/SMB, sin modificar la red `default` ni habilitar forwarding.

## English

This change records **three provisional source-derived development units** (SSH, FTP/FTPS, SMB/Samba) and 25 explicit family dispositions. It validates consistency with historical, hash-pinned records, **not present-day host state or full case acceptance**. P6 historical stage files and all scientific observations remain untouched. A fixed, optional read-only nft/libvirt capture writes protected local receipts; even observed R34 table presence is not considered isolation proof. P8 remains NO-GO. CI explicitly discovers 41 R50-A and 35 R51 tests and rejects silent zero-test passes. The 54 experimental units, executor authorization, integrated A1–A10, and final risk are all pending.
