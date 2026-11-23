# ARDREC R163-F4 — Staging durable monousuario

Este incremento incorpora un mecanismo transaccional que
conserva los códigos fuente B4/B9 V2 bajo destinos nuevos,
sin activarlos y sin declararlos instalados independientemente.

La autorización se valida con firmas Ed25519 y revocación
vigente antes del journal, B4, B9 y recibo.

Se reutilizan las primitivas verificadas de R146:
archivos exclusivos, permisos privados, verificación de bytes,
bloqueo de concurrencia, sincronización durable y publicación
atómica sin sobrescritura.

Los destinos son:

- r163-b4-source-candidate-v1
- r163-b9-source-candidate-v1

Las pruebas utilizan directorios privados temporales del
usuario y cubren recuperación tras tres interrupciones,
alteraciones, procedencia de fuentes y revocación entre fases.

## Restricciones

El staging NO instala los ejecutores operativos en sus rutas
históricas, NO valida sus liberaciones R139 y NO los ejecuta.

El journal y el recibo se protegen por propiedad/permisos del
sistema de archivos en el directorio elegido. No equivalen,
por sí solos, a una atestación externa o a independencia humana.

El software no proporciona privilegios root ni habilita el
tráfico de red. Una futura entrada root necesita aprovisionamiento
externo de confianza, revisión de permisos y un contrato V3
compatible con la ejecución real.

Estado: SOFTWARE TRANSACCIONAL / NO-GO OPERACIONAL / P8=NO-GO.
