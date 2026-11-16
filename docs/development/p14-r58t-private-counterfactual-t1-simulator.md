# R58-T — Simulador T1 aislado, transaccional y verificable

## Propósito

Comprobar el compromiso **exclusivamente contrafactual** de `T1: PREPARADO → PENDIENTE` sin modificar `GlobalState`, las unidades de servicio ni el motor operacional. No se introducen decisiones de autorización real. El motor verdadero `transition_service` permanece fuera de este incremento.

## Entradas y autoridad

Se vuelven a comprobar los recibos R58-R y R58-S: las 29 solicitudes siguen `DENIED`; solo 8 casos SSH cumplen la condición lógica contrafactual de A3. La entrada al simulador exige las fuentes de R58-S ya verificadas. En ausencia de recibo auténtico se bloquea; una autorización aparente provoca bloqueo.

## Almacenamiento y recuperación

Se crea una base SQLite por sesión bajo un directorio absoluto privado (700), propiedad del usuario, distinto de los directorios de propuesta y decisión. La base (600) contiene `meta`, `cases`, `events`. La entrada del directorio se sincroniza tras crearla. Solo T1 contrafactual está implementada; no se admiten transiciones T2–T10. `BEGIN IMMEDIATE`, `synchronous=FULL`, claves foráneas, validación de integridad, contador CAS, solicitud idempotente y cadena SHA-256 con anclaje a R58-S. Un fallo anterior al commit de un evento revierte tanto el estado como el evento. Un archivo de inicialización incompleto o vacío se bloquea para revisión, sin autorrecuperación destructiva.

Los sucesos se revalidan en orden antes de aceptar cualquier lectura o escritura. Corrupciones, pérdida de un caso, duplicación de identificadores, cambios de fuentes, modificaciones del SHA, permisos incorrectos y reutilización conflictiva de la solicitud se rechazan. El SHA-256 asegura comprobación de integridad, no autenticación frente a un actor que controle el contenido y pueda recalcular hashes. Se admiten como máximo ocho cambios simulados para la sesión fijada; el catálogo mantiene un máximo de 54 casos.

## Separación y límites

- Dos transiciones T1 **del simulador** en la demostración (dos casos SSH), con recuperación y repetición.
- Cero transiciones operacionales; R58-S sigue denegando **todos** los casos.
- Ninguna VM, SSH, FTP, SMB, red, ejecutor Rust, escritura de estado operacional, A5, evidencia A6 acreditada, riesgo final Rf o publicación A9.
- Repositorio público por decisión del proyecto; no incluir credenciales ni resultados técnicos sensibles.
- F11 inactivo, R34 DENY, P8 `NO-GO`.

## Validación

`PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58t_*.py' -v`

`PYTHONPATH=src python3 -B scripts/ardrec_p14_r58t_counterfactual_t1_demo.py --synthetic-offline`

Esta es una prueba de un mecanismo de persistencia contrafactual **no una declaración de algoritmo A1–A10 completo** ni validación experimental de las 54 unidades.
