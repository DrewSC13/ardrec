# P8-R17 — cierre material: diagnóstico estructural de 29 perfiles

El contrato compara las fuentes públicas fijadas P8-R1 (12 campos), P8-R10 (29 intenciones), P8-R13 (gramática simbólica) y P8-R15 (25 riesgos, 238 vínculos). La evaluación es **sólo lectura** y **deny-only**. Impide presentar un SHA candidato de la imagen QCOW2 como pin de runtime, o una gramática abstracta como `argv`.

- 29 perfiles: SSH 8, FTP 10 y SMB 11.
- 12 vinculaciones materiales por perfil: 348 pendientes en el corte `b0e8050`.
- 9 obligaciones comunes por perfil y 2 adicionales para cada una de las 5 escrituras: 271 vínculos de obligación sin acreditar.
- 238 asociaciones conservadoras entre riesgos y perfiles; no equivalen a prueba causal o compatibilidad funcional.
- Los cinco perfiles de escritura: `SSH-T07-BASE`, `FTP-T07-BASE`, `FTP-T08-WRITE`, `SMB-T08-BASE`, `SMB-T09-WRITE`.

El auditor exige que las cuatro fuentes continúen en estado no autorizado. Si aparece una vinculación nueva en las fuentes históricas, **falla cerrado** para exigir un nuevo contrato de revisión; no la adopta automáticamente. Se rechaza cualquier manipulación de perfiles, órdenes, rutas candidatas, valores de control, material CLI o políticas de limpieza.

## Reproducir

```sh
python3 lab/verify_p8_r17_material_closure.py
python3 -m unittest discover -s lab/tests -p test_p8_r17_material_closure.py -q
```

## Criterio de salida del punto P8

Este incremento **no cierra P8**. La primera obligación material es obtener evidencia de configuración efectiva del cliente observado, CLI y dependencias con un ensayo aislado aprobado y delimitado. Después debe existir enlace confiable por caso de los 12 campos, autoridad/revocación, entorno, presupuesto finito, captura y limpieza. Un reporte con `PASS_DENY_ONLY...` certifica la **corrección del diagnóstico sobre los artefactos existentes**, no la disponibilidad operacional del perfil. No ejecutar VM, cliente invitado, shell remoto ni despachar.

**EN:** Deny-only pinned, cross-protocol material-closure gap oracle. No operational authorization, subprocess, argv renderer, executable, secrets or network usage.
