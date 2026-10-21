# Verificación de persistencia / Persistence verification

## Español

**Implementación:** almacén operacional Python, diario de intención/resultados,
generaciones inmutables, integridad, exclusión de escritores y recuperación.
**Verificación funcional del componente:** 40 métodos de prueba, con 68 casos de
interrupción real de procesos mediante SIGKILL.
**Aceptación funcional del sistema completo:** pendiente.
**Validación experimental y cortes eléctricos de hardware:** no ejecutados.

Fuente: TESIS ARDREC §§3.4, 3.5, 3.9, 3.10.1–3.10.2 y tabla 3.18.
Decisiones de almacenamiento: [ADR 0005](../adr/0005-persistencia-y-diario.md).

Desde la raíz del proyecto:

```bash
.venv/bin/python scripts/verificar_persistencia.py
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests/unit -p 'test_*.py' -v
```

Las pruebas trabajan exclusivamente en directorios temporales. No modifican
almacenes operacionales ni ejecutan herramientas de evaluación de servicios.
El workflow existente descubre `test_persistence.py` mediante la suite unitaria;
no se añaden dependencias ni acciones de terceros.

| Familia | Oráculo independiente del éxito de escritura |
| --- | --- |
| Intención | Tras recuperación conserva identidad y reserva; una segunda reserva se rechaza. |
| Resultado durable | Mantiene reserva y contador cero hasta publicación. |
| Incorporación | Generación 2, recibo presente y contador 1 aparecen juntos. |
| Ausencia verificada | Recibo confirmado, contador de ejecución 0. |
| Duplicados e incertidumbre | Duplicado exacto no cambia `HEAD` ni borra incertidumbre posterior. |
| Candidatos | La fase local puede cambiar; la generación confirmada permanece anterior. |
| Integridad | Archivo alterado, objeto faltante o cadena incoherente impiden abrir. |
| Tipos | Un booleano no sustituye a un índice ni a un entero dentro de una generación. |
| Concurrencia | Segunda sesión/proceso bloqueados; sesión heredada por fork inutilizable. |
| Fallos de E/S | Escrituras cortas se completan; escritura cero, ENOSPC y EIO no reciben confirmación. |
| Acuse perdido | Puntero nuevo verificado conserva reserva o incorporación sin repetir efectos. |
| Recuperación repetida | Mismo estado y huella, sin nueva ejecución ni segunda incorporación. |

### Matriz de interrupciones

Cada objeto recorre seis fronteras: creación del temporal, escritura parcial,
escritura completa, sincronización de archivo, instalación y sincronización de
directorio. El puntero/acuse recorre ocho: creación, escritura parcial, escritura
completa, sincronización, antes de reemplazar, después de reemplazar,
sincronización del directorio y entrega del acuse.

| Operación | Fronteras | Casos |
| --- | --- | --- |
| Inicialización | Generación + diario + puntero/acuse | 20 |
| Reserva de intención | Diario + puntero/acuse | 14 |
| Resultado técnico | Diario + puntero/acuse | 14 |
| Publicación de generación | Generación + diario + puntero/acuse | 20 |
| Total | Procesos hijos terminados con SIGKILL | 68 |

El padre exige terminación por SIGKILL para que un error del hijo no se cuente
como interrupción válida. Tras morir el proceso, se abre una sesión nueva y se
comprueban generación, reserva, recibo y contador. Antes del reemplazo debe
permanecer la autoridad anterior; después, la autoridad visible debe ser íntegra.
En una pérdida eléctrica real, la visibilidad tras `rename` antes de sincronizar
el directorio depende del sistema de archivos: estas pruebas no simulan la
pérdida de caché del dispositivo.

No se equipara pasar estas pruebas con verificar la autenticidad de soportes,
consultar el diario Rust, implementar A5/A9 completos ni validar el modelo
analítico o los resultados experimentales. El integrador futuro debe conservar
la regla: intención durable antes de envío, consulta ante incertidumbre y ninguna
nueva ejecución durante una reserva pendiente.

## English

**Implementation:** Python operational store, intention/outcome journal,
immutable generations, integrity checks, writer exclusion and recovery.
**Component functional verification:** 40 test methods, including 68 real process
interruption cases using SIGKILL.
**Full-system functional acceptance:** pending.
**Experimental validation and hardware power-loss tests:** not run.

Source: TESIS ARDREC §§3.4, 3.5, 3.9, 3.10.1–3.10.2 and Table 3.18.
Storage decisions: [ADR 0005](../adr/0005-persistencia-y-diario.md).
Run the two commands in the Spanish section from the project root. Tests use
only temporary directories and never execute service-assessment tools. Existing
CI discovers `test_persistence.py` through unit discovery; no dependencies or
third-party actions are added.

| Family | Oracle independent of successful writes |
| --- | --- |
| Intention | Recovery retains identity/reservation and rejects another reservation. |
| Durable outcome | Reservation and zero execution count remain until publication. |
| Incorporation | Generation 2, receipt and count 1 appear together. |
| Verified absence | Confirmed receipt with zero physical execution count. |
| Duplicates/uncertainty | Exact duplicates neither alter `HEAD` nor clear later uncertainty. |
| Candidates | Local phase changes without advancing confirmed generation. |
| Integrity | Corruption, missing objects or inconsistent chains prevent opening. |
| Types | Booleans cannot replace indices or generation integer fields. |
| Concurrency | Second writer/process blocked; inherited sessions unusable. |
| I/O failures | Short writes complete; zero writes, ENOSPC and EIO never acknowledge success. |
| Lost acknowledgement | Verified new authority retains reservation/incorporation without repeating effects. |
| Repeated recovery | Same state/hash, no extra execution or incorporation. |

### Interruption matrix

Each immutable object has six boundaries: temporary creation, partial write,
complete write, file synchronization, installation and directory synchronization.
The head/acknowledgement has eight: creation, partial write, complete write,
file synchronization, before replacement, after replacement, directory
synchronization and acknowledgement delivery.

| Operation | Boundaries | Cases |
| --- | --- | --- |
| Initialization | Generation + journal + head/acknowledgement | 20 |
| Intention reservation | Journal + head/acknowledgement | 14 |
| Technical outcome | Journal + head/acknowledgement | 14 |
| Generation publication | Generation + journal + head/acknowledgement | 20 |
| Total | Child processes terminated by SIGKILL | 68 |

The parent requires SIGKILL termination; a child error cannot masquerade as a
valid interruption. A new session checks generation, reservation, receipt and
count. Before replacement, previous authority remains; after replacement, visible
authority must be consistent. Actual power loss between rename and directory
synchronization depends on filesystem behavior; these tests do not emulate loss
of device-cache contents.

Passing these tests does not verify external supports, query the Rust journal,
complete A5/A9, or validate analytical/experimental outcomes. Future integration
must preserve durable intention before dispatch, queries on uncertainty, and no
new execution while a reservation remains pending.
