# R117-F5C — Cierre transaccional de fuentes

## Propósito

F5C implementa una comprobación estructural determinista
del resultado de instalación F5B. Es un incremento SOURCE_ONLY
y no confiere autoridad operacional.

## Contrato de cierre

Se requieren los 39 archivos exactos del candidato F5A,
incluyendo 36 fuentes ejecutables, el manifiesto, catálogo
y lock.

Se requiere un recibo F4 exactamente derivado de las fuentes
y tres archivos de release: receipt.json, approval.json y
approval.sig.

El diario transaccional exige exactamente:
intent.json, prepared.once, pilot-visible.once,
release-visible.once y complete.json.

El cierre comprueba vínculos SHA-256 del candidato,
aprobación, manifiesto y recibo, además de flags
explícitos de no autorización de arranque o tráfico.

La falta de complete.json o de cualquiera de los
marcadores provoca rechazo. Los resultados parcialmente
publicados nunca se reconocen como cierre estructural.

## Alcance de la evidencia

Las pruebas usan una firma sintética de 64 bytes que solo
verifica forma y no autenticidad. El resultado declara
siempre ed25519_verified=false y boot_authorized=false.

La verificación de propietario root, permisos, cadenas de
directorio, autoridad independiente, revocación, durabilidad
física y prueba de firma deben incorporarse en una puerta
privilegiada de confianza antes de aceptar una release.

El verificador F4 original continúa sin comprobar este
contrato. No utilizar F5C para permitir arrancar VM ni
para retirar el bloqueo de F5B --apply.

## Restricciones preservadas

Sin sudo, instalación, arranque, nftables, red o cambios
al histórico R116. P7=DRAFT, A6=ND, P8=NO-GO.
