# ARDREC P14 / R58-C — F11 preflight y A6→A7→A8→A9, sin despacho

## Origen y estado

- Base exacta: `main` tras PR #134, merge `0153c8513efe10192ff0704a2132756a4517ed54`.
- R58-B ya incluye cuatro **candidatos fuente** para guardia/hook/watchdog, no instalados.
- F11-P registró `BLOCKED_F11_BOOT_GUARD_UNSTARTED`; R34 DENY y filtro DROP ALL verificados, cuatro VM apagadas, red FTP inactiva.
- Cero familias de catálogo técnicamente aceptadas, cero validaciones experimentales, `P8=NO-GO`.

## Una entrega, dos frentes sin dependencia de arranque de VM

### 1) F11: preflight de instalación de solo lectura

`python3 -B scripts/ardrec_p14_r58c_f11_deployment_plan.py --verify-offline`

Verifica los hashes exactos de los cuatro candidatos R58-B, los cuatro destinos fijos y produce una propuesta JSON. No comprueba el host; `host_audited=false`.

`python3 -B scripts/ardrec_p14_r58c_f11_deployment_plan.py --host-readonly`

Reutiliza directamente la auditoría F11-P vigente para autenticar bundle raíz, systemd, nftables y filtro libvirt, y añade consultas libvirt `--readonly` al inventario de VM. Inspecciona solo metadatos de los cuatro destinos potenciales en `/etc` y clasifica rutas existentes/symlinks como conflictos de revisión, no las modifica. Detecta invitados ajenos activos para análisis del impacto de un reinicio del daemon. El retorno **21** implica un inventario leído, pero TODAVÍA BLOQUEADO. El retorno **23** indica fallo de lectura o discrepancia: detenerse. En ningún caso autoriza instalar ni reiniciar.

El hook R58-B propuesto DENIEGA todo arranque de VM R33: ni siquiera tras instalarlo podrá arrancarse FTP hasta una futura política acotada y autorizada. `Requires` + `After` en libvirtd no sustituyen una prueba negativa de arranque manual, ni el timer periódico sustituye un watchdog instantáneo.

### 2) Algoritmo: A6→A7→A8→A9 documental con módulos existentes

`PYTHONPATH=src python3 -B scripts/ardrec_p14_r58c_a6_a7_a9_chain.py --synthetic-offline`

Este comando utiliza el recibo **sintético existente** de R37, el caso y sesión R26, el clasificador documental A6, el oráculo racional A7, el dictamen A8 y el recibo durable A9 de R28. Verifica la integridad y construye una cadena enlazada por SHA-256 que une recibo de soporte, admisión, sesión, selección, límites, dictamen de parada y recibo A9.

Una admisión documental de A6 nunca acredita verdad técnica: por ello A6 sigue `ND`, A7 solo calcula un oráculo **sin contribuciones confirmadas**, A8 recomienda pausa sin aplicarla y A9 crea solo un recibo **de desarrollo**, no una generación operacional. No se atribuye `Rf` confirmado, ni se encienden VM, ni se autoriza la ejecución P8.

Puede utilizarse una fuente de revisión fuera de Git suministrando `--receipt RUTA --support RUTA --as-of-utc AAAA-MM-DDTHH:MM:SSZ`. El tiempo procede de la declaración explícita del operador; la entrada no produce certificación externa por sí sola.

Solo una orden expresa `--write-development-receipt DIRECTORIO_PRIVADO_EXISTENTE` guarda el recibo de desarrollo A9 mediante la implementación idempotente existente, en un directorio privado ya creado por el operador. No crea directorios, no escribe en Git, no sustituye recibos discrepantes ni publica generaciones. El CLI no dispone de modo de VM o tráfico.

## Límites de aceptación

Se comprueba la conexión de software y su inmutabilidad, **no** se demuestra que A6, A7 o A9 estén operacionalmente completos frente al marco de tesis. No existe, en esta fase, la cadena de testigos independientes de evidencia técnica, autoridad, identidad de captura, revisión de contradicciones y generación técnica. Esas obligaciones siguen pendientes para aceptar Rf real.

## Validación

```text
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58c_*.py' -v
python3 -B scripts/ardrec_p14_r58c_f11_deployment_plan.py --verify-offline
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58c_a6_a7_a9_chain.py --synthetic-offline
```

El workflow de CI ejecuta únicamente las pruebas offline de ambos frentes. No hay modo privilegiado en CI. **Nunca se debe interpretar un `PASS` de CI como permiso para un cambio físico.**
