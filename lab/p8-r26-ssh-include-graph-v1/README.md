# ARDREC — P8-R26 / Modelo acotado de candidatos Include SSH

Se crea un **modelo público puro, exclusivamente sintético** para reconstruir una expansión candidata de `Include` con recursos finitos; no se vuelve a leer la QCOW2 ni se extrae configuración privada. A diferencia del recuento léxico R25, las pruebas sí construyen rutas ordenadas de inclusiones a partir de un inventario sintético explícito de bytes y archivos.

**Diferencia entre inventario y configuración efectiva:** las aristas son candidatas. Una inclusión bajo `Host` o `Match` solo se marca `conditional_unresolved`; no se interpreta la condición. Tampoco se reproducen el parser de OpenSSH, la precedencia de opciones, la expansión de tokens, configuraciones de usuario, CanonicalizeHostname, `Match final`, CLI overrides ni el entorno. El único patrón global permitido es `/etc/ssh/ssh_config.d/*.conf`; las demás referencias admitidas son literales `.conf` del mismo directorio fijo. Los nombres son etiquetas en memoria, no rutas que el programa abra.

La única etiqueta de alias permitida es `/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf` → `/usr/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf`. El modelo **no inspecciona symlinks reales**, no valida el enlace por su cuenta y jamás sigue rutas. Una declaración sintética de alias no amplía la excepción material verificada en R25.

## Límites estrictos

- 33 fuentes, incluyendo el archivo raíz; 262144 bytes por fuente y 1048576 bytes total.
- 96 aristas, 96 visitas recursivas, profundidad máxima 8; 8192 líneas por archivo, 4096 bytes por línea.
- 8 tokens máximos por `Include`. Archivos UTF-8 no vacíos sin NUL, rutas exactas no escapables.
- Bloqueo ante ciclos, includes sin datos, patrones fuera del alcance, comillas, expansión `%/$/~`, `Match exec`, enlaces no previstos o ambigüedad.
- El modelo no puede probar que un catálogo sintético corresponde a archivos realmente existentes o completos en la QCOW2.

## Verificación aislada

```bash
python3 -B lab/verify_p8_r26_ssh_include_graph.py
python3 -B -m unittest discover -s lab/tests -p test_p8_r26_ssh_include_graph.py -v
```

Verifica un fixture congelado con 17 escenarios y 37 pruebas unitarias independientes. Ninguna suite inicia `ssh`, `ssh -G`, `sftp`, VM o libguestfs. No se crea ni edita evidencia privada.

## Frontera de P8

R25 posee un recibo privado SHA-256 `eee28ad26a1d775b2d1f6215410ce072d64b1ea3a209567f8493848f4483fe5c`, comprobado por el operador. R26 **no lo autentica directamente**; es un ancla documental, no los bytes de los archivos. El siguiente paso material, previa autorización diferenciada, requeriría observar el contenido o una proyección privada de `Include` desde la imagen congelada, comprobando nuevamente la identidad del origen. Hasta entonces el árbol real no está resuelto. P8, AL-06, AL-07 abiertos; P9/A1–A10 pendientes. 29 perfiles bloqueados, 348 vinculaciones y 261 barreras históricas siguen sin aprobar.

**EN:** Deterministic, bounded, fully synthetic SSH Include candidate-graph model, not effective OpenSSH configuration, physical acquisition, credential disclosure or execution authorization.

## FIX1 — Herencia de contexto no resuelto

Los descendientes de un `Include` condicionado por `Host`/`Match` conservan `conditional_unresolved=true`, incluso si el archivo descendiente no declara una condición local. El campo `conditional_context_inherited` distingue procedencia heredada de contexto local. Se prohíbe también el criterio sintético `Match !exec`. La marca es conservadora, sin evaluar OpenSSH; las condiciones que un archivo incluido pudiera transmitir al regresar al llamador siguen fuera de alcance y nunca se consideran configuración efectiva.
