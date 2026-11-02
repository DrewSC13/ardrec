# Laboratorio / Laboratory

## Español

Diseño de referencia: [Prometheus compacto v1](design-v1.md).
El inventario es información comunicada por el operador, no una inspección remota.
El diseño no acredita despliegue, aislamiento físico ni autorización de ejecución.

- [Infraestructura observada](host-inventory-v1.json).
- [Topología propuesta](topology-v1.json).
- [Plantilla de autorización, no ejecutable](authorization-template-v1.json).
- [Plan de comprobaciones físicas](verification-plan-v1.json).
- [Vínculos y obligaciones conservadas](../docs/traceability/laboratory-design-v1.json).

Validación documental: `python3 lab/verify_design.py`.
La plantilla de autorización permanece incompleta deliberadamente. Debe completarse en
un registro privado separado antes de ejecutar pruebas; este diseño no concede permisos.
Los pasos 4 y 5 implementarán servicios y comprobarán restauración/aislamiento.

## English

[Compact Prometheus v1](design-v1.md) is a reference design based on operator-reported
inventory. It establishes neither deployed isolation nor execution authorization.
Run `python3 lab/verify_design.py` for document consistency only. Complete a separate
private authorization before execution. Steps 4 and 5 implement and verify the lab.
