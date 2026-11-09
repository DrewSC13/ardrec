# ARDREC — P8-R11: fuentes documentales del runner (propuesta)

**Base protegida:** `4412a1093eafbfcf61b52c647963511f01725576` (P8-R10 integrado, PR #43 y CI de pre/posmerge aprobados). **Alcance:** exclusivamente punto 8 — definición verificable de perfiles de ejecución, todavía bloqueados.

**Novedad de R11:** registro de siete manuales Debian en la imagen QCOW2 del runner con sus SHA-256 y tamaños reportados; reproducción opcional en solo lectura sobre la imagen fijada y comparación exacta de declaraciones `Depends` de cuatro paquetes. Asociación documental explícita a los 29 contratos semánticos R10, sin presumir su compatibilidad funcional.

**Frontera técnica:** el contenido de los manuales no ha sido revisado para probar opciones concretas. No existe gramática de argumentos aprobada, renderizador de `argv`, secuencia SSH remota ni comando `smbclient -c` autorizado. `Depends` no demuestra dependencia resuelta ni proceso seguro. Permanecen pendientes cadena de confianza del binario y su custodia en ejecución, aislamiento, credenciales privadas, casos/destinos P6, límites piloto, capturas, limpieza, revocación y comprobación efectiva por operación. Los manuales y sus huellas son observaciones del operador, no una atestación de tercero.

**Resultado previsto de este cambio:** 7 fuentes manuales; 4 declaraciones `Depends`; 29 relaciones documentales candidatas; 0 opciones verificadas; 0 capacidades funcionales demostradas; 0 perfiles autorizados; 0 casos; 0 despachos; 0 ejecución de invitados; AL-06/AL-07 y siete obligaciones abiertas. Sin P9 ni A1–A10.

**Estado:** documento de propuesta hasta CI, firma e integración protegida. Los cortes históricos previos no se reescriben.

**EN:** P8-R11 proposes versioned, operator-reported read-only runner-manpage and dpkg dependency evidence. This is source provenance only; no CLI semantics, executable grammar, authorization, budget, lab execution or algorithm implementation.
