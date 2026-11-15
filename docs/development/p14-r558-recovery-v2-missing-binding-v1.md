# ARDREC P14–R55.8 — Restauración deny-only V2 ante binding ausente

## Base comprobada

`main=04dc845983ffe53925498c47e142b3924319bf1c`, PR #129 fusionado. R55.7-F2 emitió `PHYSICAL_DENY_AND_TIMER_PASS_NO_GO` con SHA-256 `9a8ec90ff3a411c059d54e7b9933546705e16b968bec0c1121b5869c7e84c37d`. R55.2-F1 y R55.6 siguen autenticados. Los recibos privados no se suben a Git. El repositorio continúa público por decisión del operador.

## Hallazgo material

El recuperador R55.5, ya instalado y autenticado en `/var/lib/ardrec/r555-deny-guard`, restituye nftables R34 y bindings *originales* o *candidatos conocidos*. Sin embargo, si un intento de reemplazo termina entre `nwfilter-binding-delete` y `nwfilter-binding-create`, el binding desaparece del inventario y el recuperador R55.5 se bloquea. La documentación libvirt confirma que `nwfilter-binding-delete` desasocia el filtro y retira sus reglas inmediatamente. Esto **NO es** un error de R55.7: la prueba anterior comenzó en DENY con ambos bindings presentes, no inyectó fallos parciales.

## Entregable R55.8

- `ardrec_p14_r558_root_recover.py`: **recuperador v2** deny-only, ruta fija nueva `/var/lib/ardrec/r558-deny-guard`. R55.5 permanece inalterado. Toda recuperación empieza aplicando R34 DENY y verificando su readback. Consulta la identidad exacta del dominio, UUID, MAC, TAP y red. Consulta el inventario de bindings; si falta el TAP, puede recrear exclusivamente el XML original SHA-256 autenticado. Si el binding existe pero es desconocido, se bloquea conservando DENY. Si un comando falla, no ejecuta un bypass ni da éxito falso. Rechaza rutas de paquete variables y modos ALLOW. Esta lógica **aún no está ensayada físicamente** bajo ausencia real de binding.
- `r558_recovery_contract.py`: prepara 7 archivos root autenticados (mismo plan R55.2-F1, política deny exacta y v2 con hash fijo). Establece 9 operaciones `install` permitidas y preserva R55.5.
- `ardrec_p14_r558_bundle.py`: cuatro modos con fronteras explícitas: `--verify-offline`, `--prepare-private`, `--install-root-bundle DIR` y `--probe-root-v2-deny-only`. Los dos últimos exigen `main` integrado, R34/R33 vigentes, material privado verificado y autorización nueva mediante `/dev/tty`. **Nunca** arman temporizadores ni abren tráfico.
- Pruebas adversariales de reconcilación de binding ausente, identidad del dominio, políticas desconocidas, fallo de creación y reintento bajo simulación, R34 antes que libvirt, autoridad/alcance y manifiesto.
- CI focalizada R55.8, sin root ni efectos físicos.

## Reglas de transición

1. PR con tests y CI primero; un merge no autoriza el host.
2. Tras el merge, generar recibo privado R55.8, instalar en directorio versionado **nuevo** con autorización `AUTORIZO_R558_INSTALAR_ROOT_V2_SIN_TIMER`. El instalador comprueba SHA-256 del contenido root ANTES de ejecutar `--check-root-bundle`. Ante instalación parcial: no reintentar automáticamente.
3. Con segunda autorización `AUTORIZO_R558_PROBAR_ROOT_V2_DENY`, ejecutar restauración idempotente con host aún en DENY. No inyectar ausencia real de binding todavía.
4. Crear supervisor independiente de V2 y ensayar fallo parcial físico **solo** con R34 deny vivo y plazo de recuperación válido, antes de un futuro operador ARP/ICMP.
5. Una ventana ARP/ICMP bajo TTL no es autorización P8 ni permiso para TCP/UDP, SSH, FTP o SMB. Ningún modo R55.8 activa ALLOW, altera invitados, captura tráfico o modifica R33/R34 fuera de restauración deny autorizada.

**Estado obligatorio: `P8=NO-GO`.**
