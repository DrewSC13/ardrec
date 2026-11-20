# R116-F3 — Sesión raíz FTP-T01 de 60 segundos (fuente preparada; NO-GO físico)

## Alcance, autoridad y evidencia

**Objetivo:** integrar una sesión de intento único FTP-T01 en el anfitrión Linux para un piloto P7 *excepcional* y expresamente aprobado. No se confunde esta excepción con P8 ordinario: P7 sigue `DRAFT_NOT_CALIBRATED`, A6 permanece `ND`, A7/A8/A9/A10 no publican resultados y el catálogo continúa sin ejecución general.

**Prerequisitos independientes:** commit R116-F3 firmado (`%G?=G`); stage root explícito; recuperador R116-F1 efectivamente instalado y validado; paquete histórico root R113-F6 y datos R114-F5 autenticados; autorización de alcance firmada Ed25519, permiso piloto diferente firmado Ed25519, dos revocaciones frescas firmadas por responsables independientes; pruebas de arranque SSH → runner → FTP F7/F8 y estado real SSH/runner/FTP `RUNNING`, SMB `OFF`, vínculos DENY 5 activos/1 ausente, nftables R34 DENY. Las firmas, el catálogo y el HEAD deben corresponder al mismo contrato vigente.

**NO hay autorización externa ni actas físicas acreditadas en este incremento.** Su instalación **solo añade código fuente, pruebas, documentación y CI**. No ejecuta `sudo`, no copia código a `/var/lib`, no cambia nftables ni libvirt, no arranca VM, no habilita redes ni arma un temporizador.

## Archivos

- `src/ardrec/coordination/r116_f3_pilot_session_policy.py`: comprobaciones puras de presupuesto, topología 5/1, vencimiento firmado, ventana restante de temporizador systemd y gramática limitada de R34 FTP.
- `scripts/ardrec_p14_r116_f3_root_pilot.py`: implementación candidata de controlador raíz para **una** conexión FTP/control desde el runner. Verifica firmas y revocación con fuentes fijadas, exige historial F8, confirma DENY, consume marcador antes de preparar operación, arma el respaldo F1 antes de un posible ACCEPT, comprueba margen temporal y revocación repetidamente, transiciona solo `runner_ftp` y `ftp` a candidatos fijados, aplica exclusivamente la política FTP y vuelve a DENY. Si termina o falla, intenta recuperación F1 y conserva el temporizador independiente. Genera un recibo raíz inmutable; no acredita A6 ni congela P7.
- `scripts/ardrec_p14_r116_f3_root_stage.py`: etapa privilegiada **separada**, no invocada por el instalador de fuentes; exigir commit firmado y limpio y copiar el cierre transitivo de código Python a directorio privado propiedad de root, sin tráfico ni escritura de reglas.
- `lab/operational-controller/r116-f3-root-source-lock-v1.json`: 31 huellas de cargas útiles (controlador + 30 módulos) fijadas por SHA-256, incluidas dependencias de firma y preflight.
- `lab/tests/test_p14_r116_f3_root_pilot_window.py`: 46 pruebas negativas y positivas sin red, sudo ni host.

## Condiciones de seguridad observables

1. **Admisión:** `--inspect-root` solo podrá devolver una revisión positiva si existen documentos externos vigentes, el recuperador F1, la topología y el historial F8 autenticados; **no abre puertos**.
2. **Separación:** `--execute-pilot` es una invocación privilegiada posterior, explícita, no ejecutada por esta entrega. Requiere stage root que **no está realizado**. El código de R114 (120 s) se usa exclusivamente como fuente de datos bajo manifiesto autenticado, nunca como despachador.
3. **Orden:** verifica DENY y permisos antes de reservar; marca intento consumido en disco antes del temporizador; verifica que el temporizador autónomo F1 tenga al menos 25 s restantes antes y durante las etapas; los dos cambios `nwfilter` suceden con nft en DENY; `nft -f` con cuatro ACCEPT FTP y cuatro DROP es la última apertura.
4. **Sonda:** un solo `guest-exec` de Python, una conexión TCP desde `10.203.31.1` hacia `10.203.31.2:21`, una lectura de hasta el menor de 256 y los máximos firmados, ningún comando FTP ni autenticación. Tiempo de conexión/lectura y límite de memoria restringidos por presupuesto. Se registran QGA y la respuesta, sin emitir evaluación A6 como verdadera.
5. **Fallo:** todo error consume el intento sin autorreintento; la ruta de salida llama a F1 `--restore-deny` y a F1 `--check`; el timer de respaldo no se cancela. Si DENY no puede acreditarse el recibo queda crítico, no `PASS`. No se ejecuta ninguna restauración durante las pruebas fuente.

## Brechas reales antes de utilizar `--execute-pilot`

- Revisión de seguridad del controlador root y de su invocación concreta por un administrador independiente. **No se ha ejecutado ninguna validación física de temporizador, reglas o guest-agent en este F3.** La regresión prueba los contratos y simulaciones de comandos; no demuestra la temporización del kernel/systemd bajo una falla real.
- Determinar la existencia y autenticidad del bundle histórico `/var/lib/ardrec/r114-f5-ftp-t01-root-v1` y del F1 root guard en Prometheus. Su ausencia mantiene **NO-GO**. No se instalan automáticamente.
- Obtener la autorización de alcance y permiso piloto firmados, raíces públicas y revocaciones root, y nuevos recibos reales F7/F8. La reproducción F8 es no privilegiada y solo de trazabilidad; la verificación root del estado DENY es independiente.
- Verificar mediante prueba separada que el temporizador F1 restaura nftables y los 5 vínculos activos/1 ausente ante terminación por señal y caída del controlador, sin exceder los 60 s. No aprobar tráfico sin esa demostración.
- Integrar el resultado físico con la reserva F13 y el puente A5→A6 F14 sin declarar A6 admitida por el banner o por la firma de autorización. Es parte de R116-F4.

## Aceptación para el merge de código

Regresión sin privilegios F1–F3 + R115 + R112–R114, huellas y commit Git G, CI en PR protegido, sin archivos adicionales, no tráfico. **Aceptación de código fuente no equivale a GO operacional.** La autorización externa, verificación de watchdog real y el piloto se cierran por criterios independientes.
