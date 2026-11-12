# P8-R31 — Entrada material para revisión semántica FTP/SMB

Se parte de las entradas exactas de R14, del registro de declaraciones R29 y de los oráculos R30. No se repiten mediciones ELF ni acceso a la imagen. **21 perfiles FTP/SMB referencian 39 entradas distintas** de tres manuales reales ya adquiridos y preservados en el recibo privado R14. La CI revisa únicamente índices públicos y reglas de extracción; jamás puede acreditar ventanas materiales sin ejecutar separadamente el instrumento privado.

El modelo recorta exactamente 24 líneas como máximo a partir de cada ancla verificada por SHA. Una ventana no equivale necesariamente a una descripción completa; por eso se registra `FIXED_WINDOW_NOT_A_CERTIFIED_COMPLETE_CLAUSE` y la autoridad permanece nula. No se infieren flags seguros ni se permite un renderizador `argv`.

Pruebas públicas (sin lectura del informe ni de QCOW2):

```bash
python3 -B lab/verify_p8_r31_manual_windows.py
python3 -B -m unittest discover -s lab/tests -p test_p8_r31_manual_windows.py -v
```

Para el operador, DESPUÉS de la revisión del nuevo código y en su worktree R31, los dos comandos privados separados son:

```bash
python3 -B lab/p8_r31_private_manual_windows.py inspect
python3 -B lab/p8_r31_private_manual_windows.py extract
```

`inspect` lee y valida el informe R14 `0600` sin escritura. `extract` repite la validación y crea de forma exclusiva un único recibo R31 privado `0600` en directorio `0700`. Los dos operan exclusivamente con una captura previa, no abren la imagen. No repetir `extract` si ya existe su recibo. Compartir solo su SHA-256 y los estados de control, jamás el JSON, base64, líneas originales, rutas privadas, datos sensibles ni manuales completos.

El paso subsiguiente será revisar manualmente las ventanas junto con las fuentes originales, completar semántica por opción y producir contratos tipados *no ejecutables* hasta cumplir pruebas reales y autorización independiente. P8 sigue abierto; no P9, A1–A10 ni despachos.

**EN:** Exactly 39 bounded source windows for 21 FTP/SMB profiles. Source provenance only, with no operational authority.
