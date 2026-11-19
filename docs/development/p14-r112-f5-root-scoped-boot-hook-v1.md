# ARDREC R112-F5 — hook F11 con admisión acotada y denegación por defecto

## Identidad y estado experimental

Base local: `493305394fb8e5a9c2f55f750a5515c62938bc9c`, rama `feat/p14-r111-r114-real-lab`.
R112-F4 acreditó redes aisladas SSH/FTP/SMB activas, runner con tres NIC, cuatro VM apagadas, y F11/R34 en DENY. R112-F5 modifica **únicamente** el hook existente en `/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny`, sin renombrarlo. No arranca VM, crea permisos, ejecuta A5, cambia nft, altera nwfilter, reinicia libvirt ni publica resultados.

## Precaución con hooks QEMU

Según https://libvirt.org/hooks.html, `qemu` se invoca en `prepare begin`, `start begin`, `started begin`, `reconnect begin` y en cierre. El registro del hook depende de la inicialización del daemon: una prueba por invocación directa del archivo **no certifica** que libvirt esté utilizando la versión nueva. No reiniciar `libvirtd` de forma automática: podría afectar dominios ajenos. El mecanismo instalado se comprobará además con un ensayo negativo integrado, bajo otra autorización, antes de cualquier permiso de arranque positivo. R112-F5 NO ejecuta ese ensayo integrado.

## Contrato de admisión v2

El candidato `lab/f11-runtime-v2/00-ardrec-r33-admission` es autónomo, Python aislado `-I` (stdlib). Sin directorio `root:root 0700` `/run/ardrec-f11-boot-v1` y permiso root-owned `0600`, **los cuatro invitados R33 son rechazados**. No existe ruta de autorización positiva instalada en R112-F5.

En un incremento posterior, un permiso separado por VM podrá conceder solo un primer inicio. Requerirá identidad de dominio, nonce de 256 bits, alcance fijo, plazo máximo de 600 segundos, permisos root `0600` y una marca exclusiva `used-*` creada en `prepare begin`. `start begin` y `started begin` exigen la misma marca y la misma autorización. Un segundo `prepare` con el mismo permiso falla cerrado. FTP/SMB solo son elegibles con permisos independientes; no se conceden aquí. Las rutas `reconnect` continúan denegadas; los eventos legítimos de apagado siguen permitidos.

**Límites:** el vencimiento del permiso impide iniciar otra VM, pero **no apaga** una ya iniciada. Una indisponibilidad de sistema, rollback incompleto o reinicio del daemon durante la sesión requieren gestión separada. Si `started begin` sucede después de caducar un permiso, se rechaza; por ello no iniciar durante una ventana a punto de expirar. El directorio de permisos permanece vacío/inexistente durante esta etapa. Ningún permiso habilita tráfico: R34 y `nwfilter` siguen denegando todo.

## Instalación física bajo autorización separada

1. Confirmar firma y commit base; paquete por SHA-256. Verificar contenido y pruebas, incluidos los adversariales.
2. `--plan`: nueva captura de F11, nft, libvirt y redes; comprobar exactamente cuatro VM apagadas, tres redes activas y ausencia de otros invitados conectados a R33. Confirmar solo un hook instalado y permiso `/run` ausente.
3. `--install-deny-default <plan>` con `--i-authorize-install-root-hook-deny-only`: doble lectura antes de escribir, recibo privado de intención y marcador `install.once`. Instalar copia con root:root modo 0755 **fuera** del directorio de hooks, verificar SHA-256 y hacer un único `mv -T` sobre la ruta instalada. Sin sudo global del ejecutable Python.
4. Releer hash, propietario/modo/inventario; ejecutar *directamente* cinco controles negativos (4 invitados y reconexión) y medir otra vez VM, XML, redes, `nwfilter` y nft. Persistir recibos en `/home/cicada/ardrec-lab/r112-f5-f11-scoped-hook-v1/` con permisos privados.
5. Si una operación falla o su estado es incierto, **no reintentar**. La marca de intención impide otro intento silencioso. Inspeccionar el recibo parcial y el host. Restaurar el script original de SHA-256 `8bad829f...` únicamente mediante una intervención independiente con cuatro VM apagadas y reglas DENY verificadas.

## Estado de aceptación

`R112_F5_RESULT=ROOT_SCOPED_HOOK_INSTALLED_DENY_ONLY` confirma sustitución observada, no autoriza arranques. Aceptación de protocolo SSH/FTP/SMB: **pendiente**. Real A5: **pendiente**. Recalculación A6/A7/A9: **pendiente**. P8: `NO-GO`. Sin push/merge hasta R114.

## CI

La etapa existente `test_p14_r112_*.py` en `.github/workflows/ci.yml` descubre automáticamente la nueva suite F5 junto con las anteriores; no se duplica trabajo de CI. Las pruebas emulan contratos de invocación para evitar acciones físicas en GitHub Actions. Los resultados reales solo proceden de Prometheus y no se suben al repositorio.
