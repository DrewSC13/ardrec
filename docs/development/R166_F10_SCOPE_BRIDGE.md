# ARDREC R166-F10 — Puente de autoridad del HEAD actual

## Propósito

Permitir que los planes y arranques SSH, Runner y FTP de la rama
activa utilicen la validación independiente R116-F2 del commit firmado
actual, sin alterar la validación histórica R115-F6.

## Cambios

- R115-F7.scope_required discrimina la rama firmada activa
  de la rama histórica y comprueba HEAD, firma y árbol limpio.
- La rama activa valida el contrato, autorización Ed25519,
  confianza root y revocación mediante R116-F2.
- La importación de R116-F2 es diferida para evitar el ciclo
  R116-F2 → R115-F16 → R115-F7.
- Runner y FTP heredan el cambio a través de R116-F12.
- Se actualizan únicamente la huella F7 del lock R116-F3
  y los dos derivados exactos del cierre R116-F13.
- El manifiesto histórico de 87 fuentes permanece intacto.

## Huellas

- F7 anterior: `e55971adf1432aedd7c59163fad42e7e80b226f7d48294e6d1fbb9808fe82c36`
- F7 actual: `361e338d1948f8be31504bdd2b8108346ab96b80e58ae56ebdb32fb4de25e3af`
- Lock F3 anterior: `873069a2a9665741d504062b57f329efcd20b407de91caa6a8178d0839d0128a`
- Lock F3 nuevo: `2d15b24c9101d7615ca6f43dca3b050f1f6058ac3672592b621d3da042dd319a`

## Verificación

Las 495 regresiones anteriores se conservan.
Se incorporan 10 pruebas adicionales de ruta, firmas, revocación,
caducidad, HEAD incorrecto, confianza faltante y compatibilidad histórica.

## Límites

Este commit no migra el depósito root existente ni emite permisos.
Antes de operar se requiere reconciliar el depósito F3 con el
nuevo commit firmado, obtener firmas independientes vigentes y
acreditar los arranques físicos bajo DENY.

A6=ND; Rf confirmado=ND; A9 no publicada; P8=NO-GO.
No se ejecuta tráfico, arranque, instalación ni armamento de watchdog.
