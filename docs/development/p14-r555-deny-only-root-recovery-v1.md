# ARDREC P14–R55.5: recuperación privilegiada deny-only — contrato y ejecución desacoplada

## Procedencia y alcance

- Base exacta: `1866af3a4f0ceb64b92f39a924ef00eacf56b169` (PR #127, R55.4).
- Fuente autenticada: plan privado R55.2-F1, `plan.json` SHA-256 `b32855a66b5a7df8960e29c805a17f11b2e3b9902cd53ba8a44d6193b5fe33eb`.
- La ejecución R54.3 mostró SSH y runner activos sobre `ardrec-r33-dev-net-ssh`, con FTP/SMB apagados y R34/R33 en denegación. R55.1 y R55.2-F1 confirmaron bindings con backend `iptables` y parámetro MAC. R55.3 completó un guardia offline y R55.4 probó independencia de un temporizador **de usuario** mediante un archivo sintético, no mediante firewall.

**R55.5 introduce un recuperador real exclusivamente deny-only, pero NO LO INSTALA NI LO EJECUTA sobre Prometheus.** Los archivos se preparan sin privilegios, permanecen privados y no configuran automáticamente systemd, nftables, libvirt o las VM.

## Arquitectura implementada

1. `r555_recovery_contract.py` autentica el plan R55.2-F1 usando el verificador R55.3, exige política restauradora exacta sin reglas ACCEPT y prepara un paquete de seis artefactos más `manifest.json` con SHA-256 y procedencia. No ejecuta subprocesos ni comandos de host. Construye un comando de temporizador para `systemd --system`, pero **solo como dato verificable**, sin ejecutarlo.
2. `ardrec_p14_r555_prepare.py` ofrece dos modos: `--verify-offline` (solo lectura) y `--prepare-private-bundle <directorio-nuevo>` (escribe archivos privados `0700`/`0600` bajo la cuenta del operador). No admite `sudo`, instalación, `nft -f`, bindings ni tráfico.
3. `ardrec_p14_r555_root_recover.py` es el ejecutable previsto para una **copia posterior** en `/var/lib/ardrec/r555-deny-guard/root-recover.py`, con directorio y archivos root:root `0700`/`0600`. No se debe ejecutar mediante sudo desde el checkout editable. Exige UID efectivo 0, ruta de ejecución exacta, ausencia de symlinks, ancestros seguros, manifiesto y contenidos íntegros; usa un candado exclusivo sobre el inode del manifiesto. Sólo acepta `--check-root-bundle` y `--restore-deny`.
4. El recuperador, si se autoriza y se despliega en el futuro, aplica primero R34 deny con `nft -f -` acotado a la tabla `ardrec_r34_guard` y después verifica lectura JSON con exactamente tres cadenas y cuatro reglas DROP. Luego inspecciona los bindings: deja intactos los originales; sólo sustituye candidatos R45 estructuralmente autenticados por los XML originales; ante un binding desconocido, falla **sin borrarlo** y conserva R34 deny. Los bindings se restauran de forma secuencial, nunca de forma paralela. Se vuelve a comprobar R34. No tiene modo allow, no inicia redes/VM, no despacha P8.
5. `test_p14_r555_root_recovery.py` incluye pruebas adversariales y un fixture integrado R55.3: fallos de nft, readback, cambios de MAC/TAP/backend/propietario, XML añadido, reglas ACCEPT, extra TAP, políticas ampliadas, alteraciones del manifiesto, symlinks/rutas, temporizadores deformados, fallo parcial de `nwfilter-binding-create` y orden obligatorio R34 primero.
6. El workflow CI incorpora esas pruebas deterministas sin herramientas de red o permisos root y sin alterar la configuración del runner GitHub.

## Límites de las garantías

- El código `--restore-deny` **todavía no se ha ejecutado físicamente en Prometheus**. Las simulaciones con mocks no son testigos de restauración real. El timer `systemd --system` **no ha sido armado**, y no hay evidencia de recuperación ante SIGKILL del ejecutor privilegiado, fallos de `systemd`, caída del host o reinicio.
- En una etapa futura, un error al reinstalar un binding puede dejarlo temporalmente ausente: con R34 deny verificado continúa la contención de esa ruta, pero eso no equivale a una restauración completa.
- Un fallo anterior o simultáneo a la restauración de R34, una ausencia de la tabla, una caída del kernel/host o una modificación fuera de ARDREC **no están cubiertos** por estas pruebas.
- La exclusión de operaciones mediante candado requiere que el futuro ejecutor de mantenimiento utilice el **mismo candado**; todavía no hay ejecutor de apertura. El plan de temporizador no es una garantía operacional hasta instalarlo, armarlo, verificar que realmente se ejecuta y observar su recuperación independiente.
- El directorio privado de usuario es únicamente una fuente verificada: su contenido no debe ser ejecutado por root hasta copiarse a ubicación segura en una operación autorizada y comprobar la identidad byte a byte.

## Aceptación antes del ensayo físico de R55.6

- Repositorio privado, rama firmada, CI Python/Rust PASS y PR protegido fusionado.
- Plan fuente autenticado y paquete privado R55.5 con `SHA256SUMS` correcto.
- Instalación controlada de seis archivos y manifiesto en ubicación propiedad de root, con comprobaciones antes y después, sin usar código desde el repositorio del usuario como root.
- Comprobación `--check-root-bundle` con permisos y hashes exactos; preflight R33/R34 y bindings originales.
- Armamento real de supervisor del **sistema**, prueba de SIGKILL y fallo parcial en entorno contenido, evidencia journald y readback del firewall y bindings; autorización independiente para cada fase. No abrir ARP/ICMP hasta completar el plan de pruebas y aceptación.

En todas las fases R55.5, incluidos los mocks: `P8=NO-GO`, `guest_packets=0`, ninguna autoridad real de pentesting y ningún resultado sintético marcado como evidencia experimental real.
