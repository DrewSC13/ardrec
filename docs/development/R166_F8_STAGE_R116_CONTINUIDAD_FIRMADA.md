# ARDREC R166-F8 — Compatibilidad del staging de R116 con la rama firmada actual

## Motivo y alcance

R166-F7 acreditó la base `OFFLINE_DENY`, el guardián root DENY R116-F1
(`--check`, 4 VM apagadas) y la autenticidad del commit `8c180def`.
No acreditó autoridad R163: `AUTHORIZATION_SCOPE_INVALID`, con un único
indicador explícito de alcance divergente: `AUTH_BOOT_CURRENT=MISMATCH_OR_ABSENT`.
La revisión negativa no revoca ni reemplaza los documentos root.

R116-F3 **ya contiene un controlador candidato** de una ventana FTP-T01 de
60 segundos: verifica firmas independientes, contrato y revocación vigente;
requiere 5 DENY y SMB apagada; consume la tentativa única; arma un temporizador
root autónomo de restauración DENY a los 45 segundos; y verifica restauración
independiente. Son propiedades del código de desarrollo, **no una acreditación
física de instalación, funcionamiento, tiempo real ni permiso de tráfico**.

Los dos programas `r116_f1_root_stage.py` y `r116_f3_root_stage.py` tenían
la rama histórica fijada. R166-F8 admite además **únicamente**
`feat/ardrec-a1-a10-cierre-integral-v1`, pero exige:

- Ancestro histórico propio de R116-F1 o R116-F3, respectivamente.
- Ancestro común de la continuidad `5c7770c1548585f8eac7f50d5f68b8fb77a10614`.
- Árbol íntegro y limpio (`--untracked-files=all`), marca de firma `G` y
  `git verify-commit HEAD` exitoso.
- Exactitud de bytes del HEAD para el propio instalador, código root y el
  manifiesto/lock de fuentes; todas las huellas deben coincidir.

Se actualiza **solo** el manifiesto de cierre R116-F3 para enlazar los nuevos SHA-256 de los módulos R115-F7 y R115-F16 que F5 modificó. Los demás pines y el catálogo permanecen intactos.
La revisión rechaza cualquier diferencia adicional entre lock y fuentes.

No se cambia ningún contrato criptográfico, directorio root, pin de B4/B9,
catálogo P7, red, VM ni regla `nft`. Las acciones siguen siendo excluyentes:
`--review-source` (solo lectura) y `--stage-root` (copia de fuentes, requiere
root y aprobación externa separada). R116-F1 instalado no debe sobrescribirse.

## Autoridad R163: el desajuste de boot actual

El documento firmado R163 está enlazado al identificador del arranque del
anfitrión. Al diferir el actual, `--preflight` debe rechazarlo. **No es válido**
editar el JSON ni renovar una firma propia sin intervención del firmante y
custodio autorizado. Una reemisión válida requiere nueva autorización para
boot actual, intervalo admitido por la política, firmas verificables y
revocación fresca. El alcance `INSTALL_B4_B9_ONLY` **no autoriza arranques ni
tráfico**, aunque el staging terminara correctamente.

## Secuencia de validación

1. Aplicar el parche F8 sin privilegios, probar fuente y regresiones.
2. Crear commit Git firmado en la rama existente, verificarlo y mantener
   `P8=NO-GO`.
3. `sudo -v` de forma interactiva en la misma terminal; ejecutar **solo**
   `--review-source` de ambos instaladores desde el árbol firmado y limpio.
   Devolver `sudo -k`.
4. Contrastar el staging root R116-F3 ya existente mediante `stat`, sin
   crear o reemplazar ficheros root ni leer documentos firmados en stdout.
5. Si R116-F3 no está instalado, **no ejecutar** `--stage-root` dentro de
   estas operaciones. Requiere un procedimiento de instalación independiente
   autorizado y un control de hashes sobre su origen firmado.
6. No ejecutar `--arm-deny` ni `--execute-pilot` hasta validación temporal
   independiente del guardián, autorización firmada para el caso FTP-T01,
   cadena física SSH → Runner → FTP y topología DENY 5/1.

Aceptación de este incremento: código compatible y firmado, pruebas correctas,
revisión root sin instalación y blockers explícitos. No constituye piloto
físico completado ni observación experimental de las 54 unidades.
