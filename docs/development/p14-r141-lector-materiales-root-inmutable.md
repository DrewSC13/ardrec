# ARDREC — R141 / Adquisición de materiales root sin autoridad implícita

## Objetivo

R141 añade un lector descriptor-relativo independiente de las fuentes de la aplicación. Sirve para **reunir las entradas exactas** requeridas por R139 (B4/B9 y doce políticas firmadas, más referencia F8) sin leer desde rutas arbitrarias ni seguir enlaces simbólicos. Es una *capa de adquisición verificable*, no el instalador autónomo final.

Base esperada de la rama de trabajo: commit R140 `4c2fb55951c609ce80bef4ad40afa4a244ce0f5d`. No modificar R130–R140 ni las fuentes históricas B4/B9.

## Contrato de inventario

- Fuente candidata: `/var/lib/ardrec/r134-source-drop-v1/B4` (7 elementos), `B9` (6 elementos) y `approval.json` canónico; no se admiten otros archivos. La aprobación se captura únicamente como documento no confiable, sin conceder autoridad. El catálogo coincide con la especificación del par R135.
- Referencias de fuentes exactas: B4 `f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8`; B9 `c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3`.
- Doce políticas fijas bajo `/etc/ardrec`: diez controles de alcance/ventana/ejecución y dos controles de liberación independiente (confianza y revocación). Su mapa se conserva literalmente en el módulo.
- Referencia de arranque F8: `/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/authority/ftp-boot-paths.json`.

La lectura utiliza `openat` con `O_NOFOLLOW`, directorios vinculados por descriptor, `fstat` pre/post, identidad de la entrada tras lectura y verificación de propietario, modo 0600, número de enlaces y límites de tamaño. Los directorios de B4/B9 y del depósito deben ser privados 0700. Los directorios ancestros no admiten escritura de grupo ni de otros.

El modo de pruebas usa una raíz privada temporal propiedad del usuario. **No demuestra procedencia root**. La función `fixed_root_readonly()` se niega a ejecutarse desde el checkout: requiere un proceso root y que la fuente ejecutada coincida exactamente con `/opt/ardrec/r141-gate-v1/reader.py`. Dicha ruta **no se instala** en R141. La copia futura debe ser gestionada por un responsable independiente, con manifiesto firmado y contenido comprobado fuera de la propia aplicación.

## Estados y límites

| Aserción | R141 |
|---|---|
| Integridad de lectura relativa a descriptores | Implementada, 40 pruebas adversariales |
| SHA-256 de B4/B9 e inventario fijo | Implementados en lectura |
| Adquisición y esquema JSON canónico de 13 documentos externos | Implementados |
| Firmas Ed25519 y revocaciones de R139 | **No se revalidan aquí**; aún debe conectarse el revisor independiente |
| Procedencia de claves / firma Git bajo autoridad root | **No acreditada** |
| Copia root, instalación autónoma y publicación B4/B9 | **No ejecutadas** |
| VM, nftables, sistema, red y tráfico FTP | **Sin mutaciones** |
| A6, A9 y P8 | `ND`, sin publicación, `NO-GO` |

La salida es un conjunto de bytes que **permanece no confiable**. El recibo tiene `root_install_authorized=false`, `trust_anchor_provisioned_independently=false`, `ed25519_review_complete=false` y `git_commit_signature_independently_verified=false`, incluso si su SHA y metadatos coinciden.

## Correspondencia con hallazgos físicos

La captura R137 del 22/11/2026 acreditó R34 DENY, helper y hook F11 en `MATCH`, con cuatro VM apagadas y cero bindings activos esperados. También detectó ocho materiales externos ausentes. R141 no los recrea ni fabrica autorizaciones. Cualquier ausencia o permiso incorrecto debe detener una lectura eventual del sistema real y conservar `NO-GO`.

## Condiciones para R142

1. Fijar y autenticar la **fuente de código** de un agente instalado por un administrador independiente, no por el checkout ni por una firma emitida internamente.
2. Conectar los bytes root reales a R139, con validación de las doce claves distintas, ventanas y revocaciones actuales **antes de cada escritura**.
3. Demostrar identidad de `HEAD/TREE` y del paquete fuente mediante una atestación externa validada, nunca aceptando una afirmación de su propio manifiesto.
4. Separar dos destinos root reales de la transacción de pruebas de R135: publicación sin sobrescritura, readback, evidencia de journal, recibo, recuperación de fallo sin rebajar la autorización.
5. Ejecutar auditoría privilegiada únicamente tras un procedimiento independiente firmado y autorizado, sin `sudo` desde el checkout. No habilitar tráfico ni realizar arranques como efecto de la instalación.

## Regresión

R141 incorpora 40 pruebas locales de la fuente y mantiene las 360 pruebas de R130–R140. Prometheus deberá acreditar 400/400 antes del commit firmado; el workflow CI del branch se amplía con el nuevo grupo y no se ejecuta remotamente sin `push` autorizado.
