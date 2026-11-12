# P8-R33 — Registro de decisiones documentales humanas (DENY ALL)

Este incremento **no responde** ni resuelve automáticamente las 312 preguntas de R32. Introduce el instrumento para registrar, **una por una**, decisiones humanas privadas y delimitadas por contexto de evidencia. Permite las tres disposiciones `REQUIRES_COMPLETE_CLAUSE`, `EXCLUDED_BY_POLICY` y `DOCUMENTARY_ONLY_UNVERIFIED`. Ninguna equivale a verificación semántica completa, opción CLI autorizada, capacidad de cliente, casos o despacho.

La lectura privada se limita al recibo R32 previamente creado, fijado por SHA-256. R33 no abre QCOW2, no lee manuales originales, no inicia clientes ni imprime el contenido del recibo. No devuelve el texto de las notas al terminal. La creación de sesión (`init`) es exclusiva: el libro base se conserva en un archivo `0600` dentro de un directorio `0700`; cada nueva decisión, introducida manualmente desde un terminal interactivo, crea un evento `000001.json`, `000002.json`, etc., mediante escritura `O_EXCL`, permisos `0600` y vínculo SHA-256 al evento anterior. No se sobreescriben eventos. La cadena detecta alteraciones respecto de sus enlaces, pero **no constituye una firma independiente ni garantiza semántica**.

## Operaciones disponibles (solo operador)

Desde el worktree de R33, **después de aprobar `prepare`**:

```bash
python3 -B lab/p8_r33_private_review_ledger.py inspect
python3 -B lab/p8_r33_private_review_ledger.py init
python3 -B lab/p8_r33_private_review_ledger.py status
```

`inspect` y `init` exigen que aún no exista la sesión R33. No repita `init`. El modo `record` requiere explícitamente un `term_id` incluido en el recibo, un `question_id` entre los ocho del contrato y una disposición válida. La nota privada se solicita en modo interactivo sin eco. Ejemplo **de sintaxis ilustrativa, no de opción de cliente**:

```bash
python3 -B lab/p8_r33_private_review_ledger.py record --term 'curl.1.gz:--EJEMPLO_INEXISTENTE' --question SCOPE_AND_OPERATION_SEMANTICS --disposition REQUIRES_COMPLETE_CLAUSE
```

Este ejemplo usa un identificador inexistente deliberadamente y, por diseño, **debe denegarse**. No equivale a una instrucción de ejecución de `curl` ni debe copiarse para registrar una decisión real. Para trabajos reales se usan únicamente identificadores previamente autenticados en el recibo privado, sin compartir el recibo con terceros ni registrarlo en Git.

La CI ejecuta solamente `lab/verify_p8_r33_human_adjudication.py` y pruebas sintéticas (`lab/tests/test_p8_r33_human_adjudication.py`). No lee recibos privados, no crea sesiones, no conoce decisiones humanas y no ejecuta clientes.

## No-promoción

Aun cuando 312 disposiciones fueran registradas, no se declararía automáticamente completitud semántica, capacidad, opción aprobada, perfil habilitado ni prueba runtime. P8, AL-06 y AL-07 siguen abiertos; P9 y A1–A10 siguen sin iniciarse. Permanecen 29 perfiles bloqueados, 348 campos sin vincular, 261 obligaciones sin prueba independiente y cinco limpiezas sin acreditar.

**EN:** Offline, source-pinned, append-only human documentary dispositions, with no operational authority.
