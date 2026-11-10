# ARDREC P8-R23 — Matriz de obligaciones de capacidad/configuración

## Autoridad y límites

R23 es **solo deny-only**. Extrae relaciones verificables entre el catálogo P7 (25 familias), las 29 ranuras P8 y la compatibilidad/inventario R9. Lee el resumen autenticado de R22 de manera privada y opcional (el colector), **no** la QCOW2, ni un cargador dinámico, ni secretos, ni clientes o servicios SSH/FTP/SMB. No hay despacho, tests de capacidad operativa, P9 ni A1–A10.

Las 29 filas preservan *cada* precondición y soporte declarado y los 12 nombres de vinculación, **sin** valores de argv/credenciales ni referencias de casos. El hash de imagen de cada binario raíz es observación previa, **no** identidad de ejecución. Cinco variantes requieren acreditar ejecución y limpieza por separado; ninguna se considera aprobada. Las aserciones externas `approved=true` nunca anulan la denegación.

## Ejecución segura

Instala mediante `STAGE.py --check` seguido de `STAGE.py --stage` en el directorio de parches. El instalador verifica SHA de siete fuentes, el `main` exacto y limpio, la CI posterior de R22 y el ruleset estricto sin excepciones. Solo crea el worktree aislado y actualiza dos pasos de CI; nunca crea commit, push, PR o merge.

Verificación pública en el worktree:

```sh
python3 -B lab/verify_p8_r23_profile_obligations.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s lab/tests -p test_p8_r23_profile_obligations.py -q
```

Auditoría privada únicamente después de validar el worktree, sin `sudo` y con `umask 077`:

```sh
mkdir -p /home/cicada/Development/GitHub/ardrec-patches/ARDREC_PRIVATE_R23
chmod 700 /home/cicada/Development/GitHub/ardrec-patches/ARDREC_PRIVATE_R23
python3 -B lab/p8_r23_private_gate_audit.py --private-receipt /home/cicada/Development/GitHub/ardrec-patches/ARDREC_PRIVATE_R23/PROFILE_OBLIGATIONS_R23_PRIVATE.json
```

Se exige que el archivo destino **no exista**, directorio privado 0700, archivo nuevo 0600, fuente R22 con SHA-256 fijado. El reporte privado contiene matriz de obligaciones, nunca valores sensibles. Compartir únicamente el resumen agregado y hash del recibo R23. No repetir/acumular adivinando si hay un error a mitad de adquisición.

## Criterios de rechazo

Cualquier desviación en identidad, variante, catálogo, campos nulos, precondiciones, soportes, cinco rutas de limpieza, aprobaciones, restricciones de shell, rutas candidatas, estado del repositorio o cadena de evidencia produce fallo cerrado. El siguiente paso no modifica las 348 vinculaciones ni acredita runtime.
