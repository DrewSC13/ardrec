# ARDREC R143 — Expediente reproducible de liberación B4/B9 (solo fuentes)

## Alcance

El problema operacional no es la ausencia de código de simulación: R135–R142 ya prueban lectura, firmas y recuperación **en sandbox**. Lo pendiente es la autenticación **independiente del agente root**, de las raíces de confianza y de las autorizaciones externas. Este incremento convierte el HEAD limpio y firmado en un **expediente público de fuentes** para revisión por el responsable independiente. No genera permisos, firmas, claves, instancias ni comandos de instalación.

## Contenido y separación de responsabilidades

- Dos fuentes **operacionales** B4 y B9 V2 con SHA-256 fijados, destinadas respectivamente a `/var/lib/ardrec/r126-ftp-session-guard-v1` y `/var/lib/ardrec/r128-one-session-v2`, nunca instaladas por R143.
- Seis fuentes **solo de revisión** R135/R136/R139/R140/R141/R142. Se prohíbe importar los callbacks sintéticos R140/R142 como autorización root real.
- Un `REQUEST.json` canónico con HEAD, árbol Git, hashes, roles externos, destinos exactos y todas las guardas pendientes en falso. No contiene credenciales ni materiales vivos.
- Un `MANIFEST.json` canónico que fija el expediente. La firma Git es verificada en el checkout del operador y **no es** la firma independiente de liberación root.

Los doce roles ED25519 de documentación operacional y liberación son diferentes entre sí por contrato. **Doce nombres no demuestran doce personas independientes ni provisionan sus certificados**. La autorización del primer arranque físico SSH→Runner→FTP requiere además permisos específicos F7/F8, no cubiertos por la liberación B4/B9.

## Uso tras el commit R143 firmado

En el checkout principal, bajo usuario no root:

`python3 -B scripts/ardrec_p14_r143_external_release_request.py --prepare-readonly`

Se obtiene un ZIP de revisión fuera del repositorio, en `ardrec-patches/ardrec-r143-external-review/` (directorio `0700`, archivo `0600`). No usar `sudo` con ese comando. No reutilizar el ZIP como paquete de instalación privilegiada. El destinatario debe autenticar el HEAD, firmantes, procedencia de raíces, F8 físico y la política que permitirá o rechazará la instalación.

## Dependencias físicas y cierres no acreditados

R137 acreditó línea base offline DENY y dos fuentes R116 por hash. Los documentos externos root de alcance, piloto y F3 estaban ausentes; B4/B9 no están publicados. Las VM siguen apagadas; 5/1 físico, recuperación autónoma de 45 s, primer piloto FTP-T01 A1–A10, A6 y A9 permanecen sin acreditar. R143 **no crea material para suplir estos faltantes**.

## Próxima acción real para Entrega A

El administrador independiente debe decidir el mecanismo de provisión del agente, obtener las firmas/revocaciones vigentes y adjuntar recibo de procedencia verificable. Solo entonces un instalador *separado*, autenticado y con política root-owned podrá usar los validadores R139 y la recuperación R135 con protecciones de descriptor, y realizar publicación física B4/B9. Este expediente no concede dicha facultad.

## Invariantes

R143: `ROOT_INSTALL=NO`, `VM_STARTS=0`, `TRAFFIC=0`, `A6=ND`, `A9=NOT_PUBLISHED`, `P8=NO-GO`, `PUSH=NO`, `PR=NO`, `MERGE=NO`. No altera `main`.
