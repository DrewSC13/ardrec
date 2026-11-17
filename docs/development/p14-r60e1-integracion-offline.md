# ARDREC — R60-E1: unificación offline de tres contratos existentes

## Propósito

Ejecutar conjuntamente tres demostraciones **ya integradas en `main`** para
reconstruir un informe verificable sin escribir en el host de virtualización:

- R58-K: 29 entradas sintéticas SSH 8, FTP 10, SMB 11; 25 familias y puente A6–A8.
- R58-V: pausa/reanudación/detención modelo, handoff read-only A5/A6 de 29 casos.
- R58-O: trazabilidad sintética de A1–A10, cadena de diez etapas y recibo
  declarado local, no generación técnica.

R60-E1 exige que el checkout siga en el commit `ce9478eb04fb9e6607af534fa415542e7cbf24cd`,
sin modificaciones previas, e identifica mediante hashes Git los cinco archivos
originales utilizados (tres demos, catálogo y escenario). Solo añade tres
archivos de código/pruebas/docs en el repositorio; no crea commit ni PR.

## Ejecución

Con el código ya instalado, desde la raíz:

```
python3 -I -B lab/tests/test_p14_r60e1_integracion_offline.py -q
python3 -I -B scripts/ardrec_p14_r60e1_integracion_offline.py --run
```

El segundo comando crea un directorio `r60e1-...` de modo 0700 bajo
`/home/cicada/ardrec-lab` con tres reportes JSON, una conciliación `integrated.json`
y su `manifest.json` SHA256; todo en modo 0600 y sin sobrescritura.

## Interpretación y límites

- **29 es la cantidad demostrada; 54 es la capacidad máxima del contrato.**
  No existe una validación exhaustiva de 54 casos por esta sola ejecución.
- Reconciliar cantidades de caso, familia y etapa **no demuestra identidad
  física caso-a-caso entre los tres subcontratos**.
- No se toma el recibo F11 del host como autoridad A5/P8. A5 físico no
  ejecutado; A6 real ND; sin Rf confirmado, sin publicación A9; P8 NO-GO.
- Se conserva la distinción entre `resultado hipotético` y
  `evidencia técnica acreditada`, conforme a la tesis.
- No hay `sudo`, `nft`, `virsh`, TCP/SSH/FTP/SMB, reinicio de servicios o VM.
  Los scripts origen invocados ya existen en el commit fijado.
- Este avance es un **orquestador con conciliación de contratos y recibos**,
  no un nuevo motor integral ni validación experimental de la hipótesis.

## Siguientes prioridades

(1) Consolidar una identidad compartida firmada A1–A3 ↔ A4–A8 por unidad
(2) ampliar fixtures auténticas hasta 54 unidades, sin duplicar casos;
(3) consumir evidencia A5 con procedencia F11 independiente;
(4) ejecutar pruebas end-to-end controladas solo tras autoridad P8;
(5) cerrar análisis matemático, reproducibilidad y presentación TUI.
