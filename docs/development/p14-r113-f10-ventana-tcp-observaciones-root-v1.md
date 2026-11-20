# R113-F10 — Ventana única de laboratorio SSH/FTP/SMB

**Estado previo obligatorio:** F8R con commit firmado c6fd58e59227d95bff86a9f58a95c9af8539f22e; F9R `PASS_READONLY_HOST_ACCEPTANCE`; F6 root de seis vinculaciones y F7E forense. P8 continúa `NO-GO` incluso tras una conexión real.

**Alcance de tráfico:** runner `10.203.30.1` → `10.203.30.2:22`, `10.203.31.1` → `10.203.31.2:21`, y `10.203.32.1` → `10.203.32.2:445`, con ARP limitado. Prohibidos IPv6, red externa, puertos arbitrarios, credenciales, fuerza bruta, enumeración ilimitada y operaciones destructivas.

**Compuertas:** el código se firma con commit y exige 613 pruebas; se copia a área root 0700 con archivos 0600, enlazando por SHA-256 el plan F8R y la validación F9R. Una primera autorización permite copiar fuentes; la segunda define seis filtros NO VINCULADOS bajo DENY. La tercera permite una ventana física única con marcador `window-attempted.once` permanente.

**Orden:** F6 comprueba y acredita DENY; verifica filtros, seis identidades y runner; se arma un temporizador de sistema F6 `--restore-deny` con retraso 120 s; se confirman parámetros `systemctl show`; se sustituyen seis vinculaciones, siempre con R34 cerrado; solo entonces se aplica atómicamente el script nftables candidato; se ejecuta un solo guest-exec en runner, con conexiones limitadas, banner SSH, banner FTP y una petición SMB2 NEGOTIATE sin autenticación; finalmente F6 restaura y acredita DENY. La respuesta QGA se captura antes de interpretar el resultado. El temporizador independiente **no se cancela**, para retener la última barrera hasta 120 s.

**Evidencia:** recibos root propiedad de root, con hashes SHA-256 y replay sin host commands. Si una operación falla, queda recibo parcial; no se reintenta la ventana. Aunque un TCP conecte, eso no acredita explotación ni integración algoritmica A1–A10. El temporizador F7E fue ensayado previamente bajo DENY; la ejecución de F10 requiere acreditación física propia.

**Riesgos residuales:** `virt-xml-validate` no garantiza el comportamiento real del filtro en el dataplane. El orden transaccional y la revocación previenen aperturas persistentes si falla una transición; el temporizador es respaldo autónomo, no sustituto de la restauración inmediata. La definición `nwfilter` persiste sin vinculación después de restaurar las seis interfaces; limpieza posterior controlada separadamente si se necesita.
