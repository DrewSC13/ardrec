# ARDREC R163-F3 — Revisión firmada de fases

## Objetivo

Comprobar el contrato monousuario R163 antes de cada fase
propuesta de una instalación transaccional:

1. before_journal
2. before_b4
3. before_b9
4. before_receipt

La autorización es Ed25519 y la revocación se consulta y valida
nuevamente en cada fase. Se comprueban sesión, HEAD, árbol Git,
arranque, UID, identidad del operador, inventario y paquete.

## Integridad y límites de la evidencia

Cada revisión genera un comprobante canónico con SHA-256,
encadenado al anterior. El sistema rechaza repetición y saltos
de fase en la misma instancia.

La cadena es VOLÁTIL y NO está autenticada por una autoridad
root. No es un journal durable ni ofrece recuperación segura
entre procesos. El SHA-256 por sí solo no impide que un actor
que controle todos los comprobantes los regenere.

No constituye autorización para escribir archivos del sistema.
La procedencia de las claves, la identidad humana, el reloj,
el control de directorios privilegiados y la instalación física
no se acreditan mediante este módulo.

## Compatibilidad

R146, R139, R161, B4 V2 y B9 V2 permanecen sin cambios.
No se hacen declaraciones ficticias de independencia.

La ruta root monousuario necesita un esquema nuevo de
liberación y manifiestos compatibles, una entrada instalada
fuera del checkout mutable y un journal root durable,
con comprobación de revocación antes de cada escritura.

## Estado

SOFTWARE EN PRUEBAS / SIN INSTALACIÓN ROOT / P8=NO-GO.
