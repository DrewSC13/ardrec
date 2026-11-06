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

## Implementación de desarrollo / Development implementation

[Servicios v1](services-v1/README.md): tres servicios probados localmente y detenidos,
con versiones, cuentas sintéticas, configuraciones y evidencia documentadas. El
registro público se comprueba con `python3 lab/verify_services.py`. El diseño y el
plan anteriores conservan su condición histórica; restauración/aislamiento completos
siguen en el punto 5. / Three development services were tested and stopped. The
new record complements the historical design without asserting full restoration,
isolation, system acceptance or experimental validation.

## Restauración y aislamiento / Restoration and isolation

[Registro de desarrollo del punto 5](restoration-isolation-v1/README.md): resultados
físicos revisados, límites y condiciones de parada. / Reviewed scoped physical
evidence, limitations and stop conditions.

## Separación lógica de escenarios / Logical scenario separation

[Punto 6 / Step 6](scenario-separation-v1/README.md): tres manifiestos vacíos,
referencias y validadores para desarrollo, piloto y experimento. Las redes no
están desplegadas; la muestra no está congelada y no existe aceptación física
o experimental por este cambio. / Reserved manifests and document guards;
no network deployment, sample freeze, physical isolation or experiment.

## Catálogo operacional / Operational catalogue

[Punto 7 / Step 7](operational-catalog-v1/README.md): 25 especificaciones de
familias SSH/FTP/SMB con guardas, parámetros de referencia, soportes, límites
pendientes de pilotaje y limpieza. No existen casos derivados reales ni perfiles
de ejecución definidos; ninguna prueba se habilita. / 25 non-executable family
specifications with evidence and cleanup contracts; no live cases or profiles.
