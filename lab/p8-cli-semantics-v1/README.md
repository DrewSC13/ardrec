# P8-R12 — Interpretación de fragmentos CLI autenticados / Bounded CLI excerpt review

Este módulo contiene una revisión de **91 términos candidatos** extraídos anteriormente de **7 manuales** de la QCOW2 del runner. No incluye manuales descomprimidos, evidencias privadas, credenciales ni la copia íntegra del informe local. El SHA-256 del informe del operador es `976d239af18d3a8abc51fbe74828cb27267f44918c1c27f280b3021627658559`.

Cada registro incluye manual de origen, opción/término exacto, número de coincidencias, clasificación del fragmento, política propuesta, explicación técnica en español, número de línea reportado y hash de cada contexto. Los hashes de contexto permiten verificar la transcripción **solo si** se proporciona el informe original con `--probe`; no certifican por sí mismos una página completa de manual ni la confianza futura en el ejecutable.

Las categorías `DIRECT_DEFINITION_FRAGMENT`, `MENTION_OR_INCOMPLETE` y `AMBIGUOUS_SHORT_TOKEN` describen únicamente el **extracto disponible**. Los términos ambiguos `ssh -o` y `ssh -l` no se promueven por la mera coincidencia con `-O` y `-L`. La selección `--ssl-reqd` y la semántica completa de `--proto`, `--max-time` o `--retry` requieren extraer sus entradas completas antes de redactar CLI. La diferenciación entre SSH local/remoto, TLS de datos/control FTP, cifrado/firma SMB y escritura/consulta se mantiene.

Las políticas propuestas (`EXCLUDE_FREEFORM_OR_DOWNGRADE`, `WRITE_NEEDS_SEPARATE_CLEANUP`, `PRIVATE_MATERIAL_UNRESOLVED`, `NEEDS_COMPLETE_MANUAL`, `BOUNDED_FUTURE_CANDIDATE`) son **marcadores de revisión**. Ninguna crea una bandera de ejecución admisible. Un `smbclient -c` arbitrario o un `curl --quote` arbitrario siguen prohibidos. La eliminación por máscaras no se transforma en un mecanismo de limpieza; para los cinco perfiles de escritura se exige el contrato de limpieza separado antes de cualquier futura autorización.

Verificación source-only:

```sh
python3 lab/verify_p8_cli_semantics.py
python3 -m unittest discover -s lab/tests -p test_p8_cli_semantics.py -v
```

Comparación local adicional, si el JSON del operador está presente y no es de acceso público:

```sh
python3 lab/verify_p8_cli_semantics.py --probe /ruta/privada/ARDREC_P8_R12_MANPAGE_EVIDENCE_20261109.json
```

No se invocan herramientas del invitado ni se utiliza `sudo`. El verificador no lee el entorno ni el archivo de imagen. La revisión integral de páginas, la gramática cerrada con serialización segura, la fijación de procesos/bibliotecas en ejecución y la prueba de capacidades/aislamiento se resolverán en futuros incrementos con los límites académicos establecidos.

**EN:** All 91 term analyses are derived from bounded operator-provided excerpts. This is not a complete semantic certification of the Debian manpages. All 29 P8 profile slots are blocked. Zero approved options, argv, dispatches, authorizations, real cases and algorithms.
