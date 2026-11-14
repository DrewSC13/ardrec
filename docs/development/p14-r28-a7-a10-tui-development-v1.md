# P14-R28 · A7–A10 y TUI del recorrido de desarrollo

**Requisitos previos:** PR #93 integrado mediante merge; SHA padre dinámico comprobado por terminal; commit R27 `47af17db6bcc8dead7313829858244b6e4b79e4e` debe ser ancestro.

## Propósito

Unificar A1–A10 en un recorrido legible de terminal sin adjudicar propiedades que el sistema aún no ha confirmado. A1–A3 reutilizan el coordinador R26; A4–A6 reutilizan R27 y `BenignPipeline` de P9/P12; A7 calcula un **oráculo matemático** conforme a §3.2.8 de la tesis (figuras A7 en §3.6); A8 propone la pausa por ND sin transición aplicada; A9 registra bytes de un recibo **de desarrollo, no generación operacional**; A10 presenta diez pantallas navegables por terminal mediante `curses`.

## Semántica de A7

Con fracciones exactas y pesos positivos que suman uno:

- `Et = max([0] + contribuciones vigentes computables)`.
- `K+ = wR·R0 + wE·Et + wC·Cn`.
- `U = R0` cuando `Et = 0`; en otro caso `U = max(R0, K+)`.
- `K- = wR·R0 + wE·R0menos + wC·Cn`.
- `D = max(R0menos, min(R0, K-))`.
- `Rf_oráculo = U + D - R0`, con `R0menos <= D <= Rf_oráculo <= U <= 1`.

El ejemplo adjunto conserva `R0=1/4`, `Cn=1/2`, `Et=1/2`, `R0menos=1/4` y espera `Rf_oráculo=5/12`. **Este valor no se aplica** a SSH_DEV ni a una máquina. El `Rf` del reporte integrado es `null` porque A6 mantiene ND por carecer de evidencia técnica externa acreditada.

## Semántica de A8–A10

- A8 devuelve `PAUSAR_HASTA_EVIDENCIA_AUTORIZADA`, sin cambiar el estado `PREPARADO` ni activar los cierres ES/SA/CV/LE.
- A9 enlaza cuatro hashes de origen y conserva el recibo idempotente en un directorio local privado con escritura atómica, sin sobrescrituras. Nunca llama a la publicación de generaciones del motor operacional.
- A10 es una **TUI real**, con navegación por izquierda/derecha, h/l y salida q. El modo `--texto` produce exactamente las diez pantallas sin control de terminal y `--json` permite verificación byte a byte.
- Fuente = `SYNTHETIC_FIXTURE` o `LOCAL_BENIGN_FIXTURE`; no hay accesos a las tres VM.

## Entradas y comandos de aceptación

```text
python3 -B scripts/demo_p14_r28_a1_a10_tui.py --preview --texto
python3 -B scripts/demo_p14_r28_a1_a10_tui.py --run-local-benign --journal-root RUTA_PRIVADA --json
python3 -B scripts/demo_p14_r28_a1_a10_tui.py --run-local-benign --journal-root RUTA_PRIVADA --tui
python3 -B -m unittest discover -s lab/tests -p 'test_p14_r28*.py' -v
python3 -B -m unittest discover -s lab/tests -p 'test_p14*.py'
```

El operador no debe ejecutar `--tui` en una tubería, CI o terminal no interactiva. La TUI no inicia actividad adicional: lee el resultado del mismo ciclo previamente registrado. La segunda invocación al mismo diario prueba replay sin segundo inicio benigno.

## Límites de aceptación

- A1/A2/A3 completos: **no acreditados**. A4/A5/A6 completos: **no acreditados**. A7/A8/A9/A10 completos: **no acreditados**.
- A7 sintético: aritmética exacta comprobable; una entrada sin procedencia técnica no se transforma en `Rf` final.
- A8: recomendación, no parada efectiva ni transición de estado autorizada.
- A9: recibo local durable, no generación publicable de ARDREC.
- A10: TUI viva del coordinador de desarrollo, no TUI de ejecución de VM.
- P8 operacional continúa `NO-GO`, AL-06 y AL-07 siguen abiertos, sin claims de aceptación experimental.

## Próximo punto de integración

Conectar la admisión autorizada de observaciones de VM SSH/FTP/SMB a A6; solamente entonces permitir A7 con entradas acreditadas, transición A8, commit de generación real A9 y reporte A10 marcado como observado. Mantener el catálogo fijo de verificaciones defensivas y los límites de recursos/identidad.
