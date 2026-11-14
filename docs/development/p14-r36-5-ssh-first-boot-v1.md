# ARDREC P14–R36.5 — Primer arranque SSH bajo contención deny-first

## Alcance y autoridad

Base exacta: `a161cb625ed48d0a35251e3976f79f196b6fd039` (PR #106 integrado).

R36.4 acredita preparación de memoria y R36.3 topología inactiva. **Ninguno de esos recibos autoriza por sí mismo el arranque.** Este incremento incorpora un ejecutor nuevo en el repositorio principal con dos modos deliberadamente distintos:

1. `--preflight-only`: autentica fuentes, revalida almacenamiento QCOW2 y el estado físico de solo lectura. Crea un recibo privado con estado `READY_FOR_EXPLICIT_FIRST_BOOT` si aprueba. **No emite escrituras sobre libvirt ni nftables.**
2. `--first-boot-ssh --prior-r365-preflight <ruta> --i-authorize-r365-first-boot`: solo después de autenticar un recibo del primer modo y repetir los controles en el anfitrión, permite **únicamente** `virsh net-start ardrec-r33-dev-net-ssh` y `virsh start ardrec-r33-dev-ssh`. Ambas operaciones requieren `sudo -n`, sin shell y con argumentos literales y cerrados.

La operación activada revalida la tabla nftables, el nwfilter, tres XML de red, cuatro XML de dominio, autoinicio deshabilitado, inventario libvirt y nombres de interfaces reservadas en cada fase. Tras iniciar solo la red SSH exige que aparezca `br33d30` y ningún otro TAP/bridge reservado; tras iniciar SSH exige solo `br33d30` y `a33d30t`. Ninguna otra red o VM ARDREC puede figurar activa. Una discrepancia provoca detención y recibo de revisión; no hay reintentos ni rollback automático.

## Fuentes

Se exige el archivo fuente R32–R34 fijado por SHA-256 y con inventario TAR exacto, y los recibos privados R35 final, R36.0, R36.1, R36.3 y R36.4, unidos por sus digests internos y contenidos semánticos. La verificación del TAR reusa `verify_source_bundle`, y la de los 12 discos reutiliza `_verify_storage` del código R35 en el estado todavía apagado. El ejecutor mantiene permisos `0700` en carpetas y `0600` en recibos, no sigue enlaces simbólicos de fuentes y rechaza destinos usados.

**Límite epistémico:** verificar la presencia de nftables y nwfilter no demuestra todavía que las tramas se bloqueen en el huésped o que no exista un camino lateral en ejecución. Por eso el estado de éxito de arranque se denomina `FIRST_BOOT_DENY_POLICY_PRESENT_UNTESTED`, siempre con `guest_isolation_tested=false`, `real_service_testing=NOT_EXECUTED`, `experimental_validation=NOT_RUN`, `final_risk=null`, `P8=NO-GO`. La única forma de acreditar aislamiento de tráfico es una etapa separada R36.6 con pruebas negativas de conectividad, verificación de política aplicada e inventario de rutas.

## Operaciones excluidas

- No activar redes FTP/SMB ni arrancar FTP, SMB o runner.
- No modificar nftables, nwfilter, NAT, bridges, TAP manualmente o rutas del anfitrión.
- No hacer SSH/FTP/SMB contra los invitados, escanear puertos, lanzar pentesting ni hacer despacho ARDREC.
- No editar QCOW2 directamente, convertirlos, restaurarlos ni efectuar apagados automáticos.
- No borrar recibos, no ejecutar rollback o un segundo intento tras fallo parcial.

El código anterior R35 permanece intacto. Las operaciones del propio parche son solamente nuevas fuentes, tests, documentación y workflow; la mutación del host requiere una acción posterior, explícita y observada desde Prometheus.

## Criterios de aceptación

- CI Python/Rust de `main` y workflow específico `R36.5 first-boot safety` aprobados, commit SSH firmado y PR protegido integrado.
- Preflight nuevo, autenticado, ejecutado desde `/home/cicada/Development/GitHub/ardrec`, estado `READY_FOR_EXPLICIT_FIRST_BOOT`.
- Si se autoriza operación física, ningún otro recurso ARDREC activado; recibo sellado e inventario final exacto.
- Las pruebas de red/servicio y la aceptación funcional continúan pendientes hasta evidencia experimental independiente. `P8=NO-GO` inalterado.

## Rutas operativas

El código, las pruebas y el workflow residen en el repositorio principal. El ZIP se conserva en `.../ardrec-patches/` y los recibos en `.../ardrec-patches/r35-private-Z9vpswND/`. No se deben introducir copias de recibos privados en Git.
