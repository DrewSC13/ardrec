# ARDREC R56.0 — Programa conjunto de cierre SSH, FTPS y SMB (DEV)

**Base de código:** merge `34c8837a7cd626c36d9af2b9eaa2f593459997a7`, GitHub público. **Estado de ejecución del proyecto:** P8 NO-GO.

## Situación comprobada y separación de pruebas

1. R55.9-F1: recibo privado `r559-f1-fault-20261115T183221Z-85278`, SHA-256 `d28b78dba11457056ebcf8ad174cdfa2acfa5504de5c5bdc523094be95c9d2d1`. Demostró la reconstrucción física del binding runner ausente por el watchdog V2 mientras R34 se mantuvo en DENY. El ensayo de SIGKILL se limitó al trabajador sintético; no autoriza abrir tráfico.
2. Registro del 4 de noviembre: 17 pruebas de humo anteriores, 7 SSH, 5 FTPS, 5 SMB. Es evidencia **histórica**, no aceptación actual ni ejecución de las 25 familias.
3. R51 define tres unidades DEV y 25 familias (SSH 8, FTP 8, SMB 9) con cobertura PENDING/PARTIAL, ninguna COVERED. AL-06 y AL-07 siguen abiertas.

## Trabajo agrupado para disminuir ciclos

**Fase A — SSH completo (DEV):** verificar almacenamiento, identidades, red y denegación; mediante nueva autorización independiente, armar y comprobar watchdog, habilitar únicamente ARP/ICMP autorizado; obtener testigos positivos y negativos de paquetes y restaurar R34. Solo si esto pasa, autorizar separadamente TCP 22 de runner `10.203.30.1` a objetivo `10.203.30.2`, ejecutar los siete smoke actuales con presupuestos, registrar negativos explícitos, restaurar y acreditar deny, y mapear SSH-T01…T08 sin equiparar pruebas de humo con aceptación de familia. **No iniciar P8.**

**Fase B — FTP/FTPS DEV:** reconstruir el dominio `ardrec-r33-dev-ftp` bajo red sin enrutamiento `10.203.31.0/28`, atestar versión/configuración y TLS, sin NAT ni interfaces extra. Mantener R34 DENY hasta tener filtros y watchdog propio verificados. Después, ventana independiente con TCP 21 + pasivos TCP 50000–50009, prohibiendo FTP activo y cleartext. Los cinco controles: rechazo login cleartext, referencia sobre TLS, marcador temporal, lectura y limpieza. Evidencia separada de FTP-T01…T08.

**Fase C — SMB/Samba DEV:** restaurar/crear el dominio `ardrec-r33-dev-smb` y la red aislada `10.203.32.0/28` con controles equivalentes. Autorizar solo TCP 445, SMB2+, firma y cifrado obligatorio en share temporal; cinco pruebas: lectura, denegación de acceso restringido, escritura cifrada, lectura cifrada, limpieza. Evidencia separada de SMB-T01…T09. Prohibir NetBIOS y SMB1.

**Fase D — A1–A10 y TUI:** desarrollar contrato de admisión de evidencia por familia y generación. A6 nunca convierte salida de una prueba en evidencia por sí solo; A9 no publica generación sin controles. TUI debe mostrar etiquetas claramente distintas `HISTORICAL`, `LIVE_OBSERVED`, `CASE_PENDING` y `ADMITTED`, con fuente y hash. Mantener 54 unidades experimentales congeladas fuera de esta fase DEV.

## Entregables de R56.0

- Contrato Python `r560_service_acceptance.py` que valida rutas/identidades, configuración y las 25 familias y produce plan sin autoridad.
- CLI `ardrec_p14_r560_service_baseline.py` con modos `--verify-offline` y `--host-readonly`; el segundo realiza únicamente consultas `virsh --readonly` y reutiliza el validador de denegación real R55.3. Recibo privado 0700/0600; sin tráfico.
- Tests adversariales y CI. No se instalan servicios, no hay apertura, `P8=NO-GO`.

## Criterio de cierre por servicio

Un servicio NO puede marcarse `CERRADO_DEV` hasta acreditar en el estado actual: (1) identidad/config/versiones; (2) aislamiento con testigos positivos y negativos; (3) sesión y servicio accesible solo en su ventana explícita; (4) controles benignos de autenticación, autorización, integridad, denegación y limpieza; (5) recuperación automática y readbacks de R34 y bindings; (6) recibo con SHA-256 y hora; (7) ausencia de efectos fuera de DEV. Aun `CERRADO_DEV` **no equivale** a 8/8 o 9/9 familias A6 admitidas ni a `P8=GO`.

## Ejecución sin efectos

```
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r560*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r560_service_baseline.py --verify-offline
```

Tras merge y aprobación separada de lecturas del anfitrión:

```
sudo -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r560_service_baseline.py --host-readonly
```

No ejecutar scripts antiguos `lab/services-v1/procedures/activation-r8.py` para abrir/limpiar redes; ese registro es histórico y usa identidades de objetos de otro despliegue. No modificar `default`, Docker, puente físico, NAT, `sudoers` ni el servicio personal SSH.
