# ARDREC R81 — Prueba funcional DEV de extremo a extremo con sesión nueva

**Base fijada:** merge R80 `bac6a63e2126b12514592011ff80b09c466be44a`.

**Resultado que acredita:** ejecución integrada reproducible del *software* sintético DEV.
**Resultado que NO acredita:** aceptación funcional completa del sistema, evidencia física, prueba de penetración ni autorización P8.

## Diferencia frente a R75–R80

R75 crea una sesión nueva de generación analítica 1 y un proceso local benigno, R76 crea 25 intenciones tipadas, R78 contrasta 25 escenarios matemáticos exactos, R79 consolida A1–A10 y R80 ofrece ocho vistas de presentación. R81 **hace esas operaciones en una única invocación sobre una sesión fresca**, verifica la persistencia y conserva un recibo con los enlaces SHA de todos los pasos. Se distingue así la ejecución funcional de un proyecto nuevo de la reapertura de recibos ya existentes.

La segunda invocación `--verify` reconstruye el informe y compara los ocho textos, sin repetir A5, lanzar subprocesos, solicitar credenciales, mutar estados ni reiniciar VM. La creación rechaza directorios preexistentes, requiere ruta absoluta con padre privado `0700`, propietario no root, y deja los recibos incompletos bloqueados si hay error.

## Alcance

- A1–A10: secuencia DEV comprobada; 54 unidades **sintéticas**, aparte de las 25 familias (SSH 8, FTP 8, SMB 9).
- A5: **un solo** proceso benigno local. Nunca se interpreta como una observación SSH/FTP/SMB.
- A6: las 25 familias mantienen clasificación `ND`.
- A7: tres sensibilidades hipotéticas (E=0, E=1/2 y E=1), sin `Rf` confirmado.
- A8: cero transiciones aplicadas en la proyección.
- A9: GEN1 estructural, ninguna nueva generación.
- A10: ocho vistas R80 verificadas (resumen, etapas, A7, matriz, detalle SSH, procedencia, R38, todo).
- `system_functional_acceptance=PENDING`, `experimental_validation=NOT_RUN`, F11 pendiente y P8 NO-GO.

## Ejecución en Prometheus

Desde el repositorio canónico y como usuario no root:

```zsh
cd /home/cicada/Development/GitHub/ardrec
umask 077
PYTHONPATH=src python3 -B scripts/ardrec_p14_r81_functional_smoke.py --create --work-dir /home/cicada/ardrec-lab/r81-demo-FECHA-NUEVA
PYTHONPATH=src python3 -B scripts/ardrec_p14_r81_functional_smoke.py --verify --work-dir /home/cicada/ardrec-lab/r81-demo-FECHA-NUEVA
cat /home/cicada/ardrec-lab/r81-demo-FECHA-NUEVA/views/resumen.txt | more
```

**Precaución:** `--create` ejecuta una vez un fixture benigno local en la nueva sesión. No ejecutar nuevamente tras una interrupción; inspeccionar recibo parcial. `--verify` no reinvoca A5.

## Seguridad y trazabilidad

El SHA-256 de R81 verifica integridad local, **no crea testigo externo independiente**. R77 mantiene la frontera de autenticación documental sin pin externo aportado. La verdad técnica, los hallazgos AL-06/AL-07, la contención F11 y el catálogo P7 no están resueltos por R81. La CI añade 17 pruebas sobre creación, replay, verificación sin subprocess, separación de autoridad y rechazo de archivos alterados.
