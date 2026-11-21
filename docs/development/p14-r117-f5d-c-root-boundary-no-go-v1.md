# R117-F5D-C — Límite de confianza del snapshot

## Propósito

Integrar la inspección de F5D-B con una estructura
física controlada mediante descriptores de directorio.

Se comprueban:
- Un único diario transaccional F5B.
- Nombres y directorios esperados de piloto y release.
- Rechazo de enlaces simbólicos y modos inseguros.
- Lectura exacta de cuatro archivos de confianza.
- Correspondencia de candidato, HEAD y pruebas Ed25519.
- Cierre estructural mediante F5C y F5D-B.

## Pruebas

Diecisiete pruebas adicionales con snapshots aislados.

Se reutilizan los fixtures de F5D-B y sus firmas
Ed25519 genuinas para mantener interoperabilidad.

Las pruebas no leen ni modifican /var/lib/ardrec.

## Límite de seguridad

Los descriptores son suministrados por el llamador.
Los archivos de confianza también proceden de un
directorio facilitado por el llamador.

Por tanto, este incremento NO acredita procedencia root
del host, aprovisionamiento externo de claves ni
durabilidad frente a interrupción eléctrica.

El modo de ejecución disponible es únicamente offline.
No existe opción --apply ni --inspect-root.

La puerta operativa requiere un agente independiente,
instalado en ubicación root autenticada, con hashes
anclados y verificación de la cadena de directorios.

F5B --apply continúa bloqueado. F4 y R116 permanecen
sin modificaciones.

P7=DRAFT; A6=ND; P8=NO-GO.
