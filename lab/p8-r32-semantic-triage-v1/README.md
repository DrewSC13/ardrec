# P8-R32 — Cola privada de revisión semántica basada en evidencia R31

R31 entregó 39 ventanas roff autenticadas, acotadas a 24 líneas, asociadas con 21 perfiles FTP/SMB. R32 **no vuelve a extraer el manual**: lee **solo** el recibo privado R31 ya existente y exige su SHA-256 exacto, 39 filas completas y la igualdad de cada ancla, ventana, hash, rango y perfil con los índices públicos de R14/R31.

El resultado privado es una cola de **39 fichas** y **312 preguntas abiertas** (ocho por entrada). Para orientar una futura revisión humana, detecta señales léxicas y asigna prioridades documentales. **Las señales no certifican el significado de opciones**. La ausencia de una palabra no significa que una condición esté ausente. Una ventana no es necesariamente toda la cláusula. Ninguna ficha puede declararse completada automáticamente.

La CI pública verifica exclusivamente contrato, fuentes y pruebas adversariales **sintéticas**, sin abrir los recibos privados. La herramienta privada del operador usa dos órdenes separadas:

```bash
python3 -B lab/p8_r32_private_semantic_queue.py inspect
python3 -B lab/p8_r32_private_semantic_queue.py create
```

`inspect` autentica y verifica, sin escrituras; `create` produce **un** informe privado con directorio `0700` y fichero `0600`, y falla si ya existe. No repetir `create` ante una salida ambigua. La nueva cola **no copia bytes roff ni base64**; guarda hashes, anclas, relaciones y preguntas sin contestar. El recibo R31 permanece intacto.

Quedan pendientes la interpretación técnica humana de cada cláusula, la búsqueda de contexto extra cuando sea necesario, las pruebas del cliente y servidor efectivo, la autorización, la limpieza de cinco variantes de escritura y la definición segura de argumentos. No se ejecutan `ssh`, `curl`, `smbclient`, `rpcclient` o VM; no se abre QCOW2. Los 29 perfiles continúan bloqueados, 348 campos y 261 pruebas siguen sin resolver.

**EN:** Source-authenticated, private, question-only semantic review queue. Lexical hints are not operational proof, CLI approval, or authority.
