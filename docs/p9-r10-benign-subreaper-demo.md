# P9-R10 — Testigo benigno que sale del PGID

**Tipo:** incremento de demostración independiente; todavía no integrado con `p9_process_supervision.rs`.
**Base obligatoria del parche:** `41a8d044f3662b46e3da87a4aab09da090295a04` (corte de `main` documentado el 13-XI-2026).
**Estado P8:** contractual completo según R78-R2; operacional **NO-GO**.

## Pregunta y alcance

R09 conserva el resultado del líder cuando no ha demostrado ausencia de miembros de su grupo. El caso siguiente fuerza un fallo diferente de la inferencia «el grupo inicial se vació, por tanto no hay descendientes»: el líder termina correctamente, un proceso intermedio llama a `setsid` y deja un nieto benigno vivo en otro PGID.

El ensayo usa **solo Python local** y `prctl(PR_SET_CHILD_SUBREAPER)`, `pidfd_open`, `pidfd_send_signal`, `/proc/<pid>/stat` y `waitpid`. La instancia de CLI aislada adopta al testigo reparentado. Comprueba su PPID, PGID, UID e identidad temporal antes de enviar SIGTERM al **pidfd**; espera su salida, lo recoge con `waitpid` y prueba su ausencia. No usa `kill(-PGID)` después de la salida del líder, no acepta ejecutables externos, no hace conexiones y no requiere sudo.

## Oráculo y salidas

- **Admisible exclusivamente para el fixture:** `leader_returncode == 0`, `adopted == true`, `escaped_original_pgid == true`, `termination_reaped == true`, `cleanup_verified == true` y `outcome == PASS_BENIGN_WITNESS`. Código 0.
- **Ausencia de soporte:** `outcome == UNSUPPORTED`, `cleanup_verified == false`; código 3. No equivale a aprobado. La prueba negativa con `ARDREC_R10_FORCE_UNSUPPORTED=1` evita lanzar procesos.
- **Identidad, atribución o limpieza no demostrada:** `outcome == INCONCLUSIVE`; código 2. No usar esta salida para autorización operacional.
- La suite de tres pruebas incluye un **observador posterior al supervisor** que verifica que el PID/tick del testigo ya no corresponde al mismo proceso, una denegación de capacidad y una denegación de comando arbitrario.

La prueba identifica **el único testigo predefinido**; no atribuye todos los descendientes posibles de un proceso arbitrario. El `subreaper` no persiste si el supervisor muere. Para una garantía general tras crash se necesitará un ámbito durable delegado (p. ej. cgroup v2 bajo control explícito, con revalidación de identidad y recuperación) o una política alternativa probada. La pérdida de energía queda fuera del ensayo. No existe conexión con autorización P8 ni con el ejecutor Rust normal en este parche. No afirmar integración, CI o aceptación operacional por el resultado de la prueba independiente.

## Uso terminal de desarrollo

```bash
python3 lab/p9_r10_benign_subreaper_demo.py
python3 -m unittest discover -s lab/tests -p 'test_p9_r10_benign_subreaper.py' -v
ARDREC_R10_FORCE_UNSUPPORTED=1 python3 lab/p9_r10_benign_subreaper_demo.py
```

Registrar checkout SHA, versión de Python, kernel, arquitectura, comandos completos, código de salida, salida original, SHA-256 del log y fecha de la sesión. El reporte contiene el SHA del script. Para validar contra Rust corresponde **otra** prueba por la API normal de la crate tras leer y adaptar su implementación real; este incremento no modifica Rust.

## Trazabilidad mínima

| Obligación | Símbolo / componente | Oráculo | Estado después de R10 |
|---|---|---|---|
| P9: salida del líder no prueba ausencia de hijos escapados | `_fixture`, `_demo`, `_stat_identity` | `test_escaped_child_is_adopted_reaped_and_independently_absent` | Ensayo benigno aislado; integración Rust pendiente |
| P9: capacidad no disponible no habilita limpieza | `_subreaper_enable` | `test_capability_missing_fails_closed_without_process_launch` | Probado solo en fixture |
| P9: ninguna orden arbitraria ni despacho | `main` | `test_no_user_supplied_command_accepted` | Probado solo en CLI de fixture |
| AL-07, P9 y P12 | Supervisor Rust y recuperación | Aún no definido | **Abiertos** |

**Próximo incremento al contar con el SHA actual y fuente:** revisar la API Rust existente e integrar una supervisión trazable que comparta este oráculo y verifique su supervivencia ante límites y pérdida del supervisor. No saltar a P10 hasta cerrar la obligación de P9 que se haya seleccionado.
