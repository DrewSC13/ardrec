# ARDREC R124 — Guardián R116-F1 instalado, comprobación real de DENY y separación de temporizadores

**Alcance:** READ_ONLY / SOURCE_ONLY. No despliega ni modifica servicios de systemd, no arma R116-F1, no ejecuta nftables en modo escritura, no arranca huéspedes, no abre puertos ni genera una autorización P8.

## Origen físico identificado en Prometheus

El resultado físico del 21/11/2026, anterior a este cambio, informa:

- R123 integrado por PR #207; `main=3e5fce9ae13a6837e408486092add91e26f937a9`.
- R116-F1 `/var/lib/ardrec/r116-f1-five-one-deny-v1/root-guard.py` presente. Hash SHA-256 `c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7`, coincidente con el archivo fuente versionado de R116-F1 y su manifiesto de origen.
- `root-guard.py --check` devolvió `deny=MATCH`, `ssh=OFF`, `ftp=OFF`, `smb=OFF`, `runner=OFF`, `active_count=0`, `absent_count=6`, `p8=NO-GO`, `host_writes=0`.
- `ardrec-r34-deny-watchdog.timer` apareció `loaded/active`, con siguiente vencimiento cercano a **una hora y cuarenta y ocho minutos**. Eso no es un temporizador de recuperación de sesión FTP a 45 segundos.

R116-F1 implementa un `--arm-deny` de un solo uso que **solo puede** armarse en topología 5/1, después de comprobar que las cinco interfaces activas son DENY. Su comando fijo usa un timer de 45 segundos que ejecuta `--restore-deny`. Este mecanismo no concede permisos de tráfico y no está acreditado como invocado o probado físicamente con esta captura 0/6.

## Cambio R124

El módulo `r124_root_deny_readback.py` ejecuta exclusivamente consultas prefijadas y con `shell=False`:

1. `sudo -n -- sha256sum` sobre la ruta exacta del guardián R116, comparando con el SHA-256 anclado en el código R124.
2. `sudo -n -- python3 -I -B root-guard.py --check`, que invoca las validaciones raíz y la verificación de DENY de R116 sin escrituras.
3. `systemctl show` de R34, registrándolo **exclusivamente como timer periódico**, nunca como protección de sesión.
4. `sudo -n -- test -e` del marcador de reserva R116. Si existe, lectura canónica de `arm-consumed.once` y comprobación de la unidad concreta `ardrec-r116-f1-deny-<sesión>.timer`.
5. Segunda comprobación del SHA del script raíz después de las lecturas, para detectar sustitución inadvertida del archivo entre consultas.

Se rechazan errores de lectura, cambios de hash, JSON duplicado/no canónico, inventario irregular de huéspedes, cardinalidad de enlaces errónea, valores de autorización distintos a NO-GO, timers con nombres indebidos y marcadores incongruentes. Los comandos carecen de argumentos libres. No se recurre a `sudoers NOPASSWD: ALL` ni se ejecuta ningún comando de escritura.

## Uso en Prometheus

Situarse en `/home/cicada/Development/GitHub/ardrec`, en Zsh. Ejecutar `sudo -v` **en la misma terminal** y después:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r124_root_deny_readback.py --capabilities | more
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B scripts/ardrec_p14_r124_root_deny_readback.py --inspect --head "$(git rev-parse HEAD)" | more
sudo -k
```

La salida es un informe de lectura generado sobre el estado físico **en ese instante**, con SHA-256. No es una firma de la autoridad, no sustituye el diario F13, no se publica como una generación A9 y no atestigua la ejecución de la restauración a los 60 segundos.

## Para abrir un piloto físico futuro

Antes de cualquier `--arm-deny`, arranque o ejecución FTP-T01 sigue faltando: autorización independiente vigente y revocable; congelación/calibración P7 o piloto explícitamente aceptado por autoridad competente; control raíz de ventana, revocación y cierre; topología 5/1 realmente atestiguada; observación de la actuación temporal de `--restore-deny` ante fallo; y puente de origen físico F13→A6→A9.

La aceptación de R124 se limita a **pruebas estáticas y simuladas más lectura real del guardián instalado**, sin tomar una sesión ofensiva. La transición hacia ejecución física requerirá una aprobación independiente por sesión.
