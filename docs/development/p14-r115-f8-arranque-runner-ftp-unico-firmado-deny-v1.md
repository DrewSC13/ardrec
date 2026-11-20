# ARDREC · P14/R115-F8 — Activación runner y FTP con DENY y cadena de precedencia

Estado: **implementado en código; sin arranque físico; sin autorización P8**. Este incremento conserva la trazabilidad de R115-F1–F7. La instalación y la inspección `--inspect` son de **solo lectura** sobre libvirt/nftables y nunca ejecutan `virsh start`, habilitan tráfico ni alteran F11/R34.

## 1. Objetivo operativo

Conectar la etapa SSH de R115-F7 con **runner → FTP**, reutilizando los clasificadores físicos puros de `r112_f9_runner_boot` y `r112_f10_targets_boot`, sin ejecutar sus scripts obsoletos vinculados a otra rama/recibos. Cada etapa tiene contrato separado, autorización de arranque Ed25519 vigente, revocación independiente, sello de Git firmado, un solo intento irreversible y comprobación previa y posterior de seis vínculos `nwfilter` y nftables R34 bajo DENY.

La secuencia permitida es **SSH (F7) → runner (F8) → FTP (F8)**. SMB no se inicia en F8. El siguiente arranque se rechaza si su predecesor carece de recibo físico verificable, y ningún recibo describe un puerto FTP disponible ni una prueba de protocolo. Se preserva `A5=NO-GO`, `A6=ND`, `P8=NO-GO`, `traffic_authorized=false`.

## 2. Restricciones del núcleo

- **Código confiable:** `HEAD` de la rama `feat/p14-r115-a3-p7-a6-real` firmado `G`, derivado del commit `6ce42a1143d50f7adf69ea3159b56c0e993c45cb`, árbol limpio, fuentes F7/F8 registradas y sin diferencias frente a HEAD. El paquete instalado sin commit no permite planes ni arranques.
- **Ámbito aprobado:** contrato y autorización independientes para FTP-T01 (R115-F6), verificadas otra vez antes del intento y antes de `virsh start`.
- **Arranque aprobado:** permiso Ed25519 específico de `runner` o `ftp`, vinculado al `HEAD`, SHA del plan, contrato, autorización, rol, VM y ventana finita (máximo 120 s), con afirmación de revocación actual firmada por otro firmante independiente. Raíces de confianza suministradas externamente en las rutas root-owned definidas por F7. No son creadas ni gestionadas por F8.
- **Integridad física:** captura R115-F5 actual revalidada mediante `state_gate` de F7; DENY nftables, hash del hook F11, definiciones de VM y los vínculos activos de cada VM encendida deben coincidir antes y después. El ciclo normal con VM apagada exige la ausencia de sus vínculos.
- **Precedencia:** el plan de runner referencia el **recibo físico SSH de F7** y lo reproduce con `f7._replay_ssh`; el plan FTP reproduce primero el recibo runner y su prueba física R112-F9. Una cadena autoescrita con etiquetas `MATCH` no constituye prueba de precedencia.
- **Intento único:** `one-<rol>.once` global por rol y `boot.once` por plan se crean con exclusividad antes de cualquier escritura privilegiada. Si hay incertidumbre, error, tiempo agotado o fallo posterior al arranque, no se repite `virsh start`, no se borra ni reutiliza el lease y se preserva `incident.json`.
- **Mínimos privilegios:** solo el operador no root ejecuta la CLI; `sudo -n` está acotado a creación del lease F11, lectura de marcas/estado y un único `virsh start`. `--inspect` no utiliza estas escrituras.
- **Reproducibilidad:** planes y evidencias canónicas JSON se almacenan en directorios privados `0700`, archivos `0600`, con SHA-256 vinculados. `--replay` vuelve a ejecutar las validaciones puras y detecta alteraciones.

## 3. Interfaces

Módulo: `src/ardrec/coordination/r115_f8_runner_ftp_boot.py`.

Lanzador: `scripts/ardrec_p14_r115_f8_runner_ftp_boot.py`.

Modos:

- `--inspect --role runner|ftp`: fotografía de solo lectura, estado de etapa y NO-GO. No requiere ni concede permisos de arranque.
- `--plan --role runner|ftp --contract <ruta> --authorization <ruta> --prior-plan <ruta> --prior-boot <ruta>`: crea plan ligado a firmantes externos y recibo predecesor. Exige código ya firmado, F11/R34 actual y alcance válido.
- `--boot --role runner|ftp --contract <ruta> --authorization <ruta> --permit <ruta> --plan-dir <ruta> --i-authorize-one-physical-deny-boot`: **operación física explícita**, rechazada si falta cualquier firma, revocación, etapa o claim. Ningún instalador ejecuta este modo.
- `--replay --role runner|ftp --plan-dir <ruta> --boot-dir <ruta>`: evaluación sin tráfico del recibo original, prueba R112, instantáneas R115-F5, y precedencia.

No hay comandos de creación de firmantes, claves o permisos para autoautorizar el laboratorio. La aprobación del arranque **no equivale** a autorización de protocolos FTP-T01; activar red P8 exigirá su propia decisión y límites concretos.

## 4. Validaciones de aceptación del incremento

1. Regresión de F1–F8 y R112–R114 sin omisiones.
2. Pruebas negativas: no autoconceder P8, prohibir SMB, rechazar estados diferentes y predecesores no acreditados, cabecera Git insegura, expiración y documentos sin firma; no se repite el inicio ante error simulado.
3. Instalación exclusiva del paquete SHA-256; validación estricta de la firma Git y del conjunto exacto de cuatro archivos F7 antes del commit.
4. La instalación puede cerrar F7 mediante commit **local y firmado** y agregar F8 sin commit. No ejecuta `git push`, PR ni merge.
5. Estado físico en Prometheus hasta nueva autorización: cuatro VM apagadas; F11/R34 `MATCH`, `DENY_STAGE...` cuando corresponda; intentos físicos nuevos = 0.

## 5. Pendientes explícitos

- Permiso independiente y revocación emitidos por las autoridades externas para cada etapa. Mientras no existan, no ejecutar `--plan` ni `--boot`.
- Consolidación de F8 mediante otro commit firmado **antes** de intentar operaciones físicas.
- Primer arranque SSH, runner y FTP únicamente dentro de una ventana autorizada, con evidencias y sin tráfico FTP todavía.
- Posterior verificación de cliente/servicio y autorización P8, calibración P7 y flujo real A5→A6→A7→A8→A9→A10 con estados y generación persistente. Nada de esto se declara completado por F8.
