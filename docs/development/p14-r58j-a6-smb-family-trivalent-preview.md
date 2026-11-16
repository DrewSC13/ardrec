# ARDREC P14 / R58-J — Evaluador trivalente SMB (A6) de nueve familias

**Base:** `main` `e9fd445a417a1c07ad36cb00740d95bb8bbf2840`, PR #141.

**Fuente:** catálogo operacional P7, SHA-256 `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e`, derivado de tesis SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, tablas 3.7–3.12 y específicamente tabla 3.11.

## Lógica implementada

Las nueve familias `SMB-T01`–`SMB-T09` se examinan con la conjunción trivalente de precondiciones, distinción de ausencia, desconocido y contradicción de soportes, integridad/procedencia declaradas y seis clases hipotéticas de resultado. El código no establece identidad real del servicio, acreditación de aislamiento, credenciales ni hechos físicos: todas las guardas y soportes son datos sintéticos.

- `SMB-T01`: dialecto y transporte; negociación no implica autenticación.
- `SMB-T02`: aceptación o rechazo SMBv1 requiere respuesta observada y cliente compatible previamente declarado. No hay reintento ni fallback.
- `SMB-T03`: variantes independientes `SIGNING` y `ENCRYPTION`, con sus respectivos soportes (`SMB_SIGNATURE` o `SMB_ENCRYPTION`) y respuesta de operación. No se infiere la una de la otra.
- `SMB-T04` y `SMB-T05`: tipo de sesión invitada/anónima y autenticación de cuenta sintética; nunca implican acceso a recursos.
- `SMB-T06` y `SMB-T07`: acceso a share y listado diferenciados; lectura e integridad de archivo específico.
- `SMB-T08`: marcador nuevo sintético, verificación y confirmación independiente de limpieza; limpieza fallida implica incidencia sin confirmar riesgo.
- `SMB-T09`: `READ` y `WRITE` son casos distintos; `WRITE` exige marcador, preparación, verificación y limpieza, sin alterar archivos preexistentes.

La deducción de `NEGATIVO_VALIDO` requiere resultado negativo expresamente simulado y **todos** los soportes exigibles; falta de soporte = `INCONCLUSO`, no negativa verificada. Precedencia no habilita despacho. Una variante usa identificador de caso propio: nunca compartir el mismo identificador entre dos variantes dentro de una misma sesión y ventana.

## No acreditación y alcance

`a6_classification=ND`, `technical_truth_accredited=false`, `technical_contribution=null`, `confirmed_rf=null`, `published_generation=null`, `applied_state_transition=null`, `operational_dispatch=false`, `host_mutations=0`, `p8_operational=NO-GO` son invariantes. Las salidas `POSITIVO_VALIDO` / `NEGATIVO_VALIDO` son clasificaciones **hipotéticas**, no resultados de pruebas técnicas, y no se transfieren a A7 ni al autómata de estados.

Pruebas: `PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58j_*.py' -v`.

Demostración: `PYTHONPATH=src python3 -B scripts/ardrec_p14_r58j_smb_family_demo.py --synthetic-offline`.

Sin arranque de VM ni sockets, clientes SMB, suplantación de identidad, cambios de host, operaciones de escritura reales, acción root, libvirt/nftables/systemd o ejecución F11. El catálogo permanece en borrador no ejecutable; los nueve tipos son cobertura de reglas **sintéticas** y no nueve casos físicos.

## Continuidad

Con R58-H, R58-I y R58-J se dispondrá de evaluadores sintéticos para 8+8+9=25 familias. El siguiente paso es una interfaz A6 conjunta y un contrato de procedencia verificable por condición. Se requiere acreditación técnica independiente y autorización separada antes de aportar contribuciones a A7 o mutar A8/A9. P8 permanece NO-GO.
