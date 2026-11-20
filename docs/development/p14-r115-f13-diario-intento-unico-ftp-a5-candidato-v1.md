# ARDREC R115-F13 — Diario durable de intento único A5 FTP-T01

**Alcance:** integración de la frontera A5 con F10 (lector de saludo FTP) y F12 (presupuesto finito) mediante reserva irrevocable de un caso y comprobación reproducible del resultado. **No se obtiene autoridad A3, P8, A6 ni una generación A9.**

## Contexto y problema que resuelve

Después de F12 existe un lector acotado sobre sockets ya conectados, pero aún no hay una frontera durable para reservar el intento **antes** de que el ejecutor independiente abra una conexión, ni impedir reintentos con un `attempt_id` diferente. F13 establece esa frontera. La librería no contiene llamadas de apertura de sockets, `connect`, `virsh start`, `sudo`, `nft` ni modificaciones de P7.

## Contrato

`make_intent(...)` fija `FTP-T01`, caso derivado `FTP-T01-Sxx-xx`, sesión, evaluación, ID de intento, SHA-256 de contrato, autorización de alcance y ventana P8, además del commit Git SHA-1 completo de 40 caracteres. Las referencias son datos de enlace **no atestados** por F13; ni su presencia ni su hash equivalen a aprobación.

`reserve(intent, profile, root=ROOT)` valida la estructura y los límites F12, y crea en un directorio privado `0700` una ruta determinista **por sesión, caso y evaluación**, excluyendo ID de intento, commit, perfil y permiso de la clave de unicidad. Escribe `reservation.json` y `reservation.manifest.json` con `O_CREAT|O_EXCL`, fsync de archivo y directorio. **Debe llamarse antes de que un despachador autónomamente autorizado abra la conexión.** La existencia de la ruta consume la oportunidad; un proceso abortado no borra esa identidad.

`consume_reserved(folder, socket_ya_conectado, current_p8_guard=...)` tiene condiciones externas obligatorias, **no verificadas por este módulo**: raíz de confianza independiente, autorización y revocación vigentes, P7 calibrado/congelado, A3 completo, política F11/R34 efectiva, concesión P8 física, conexión única y recibo de procedencia. Marca `spent.json` y su manifiesto **antes de consultar el socket**, usa `MeteredSocket` F12 para aplicar llamadas, bytes y tiempo F10, produce recibo `result.json` con el candidato A5 y un manifiesto de hash, o `failure.json` y su manifiesto. Un fallo, suspensión o incidente incierto nunca autoriza reintento automático.

`inspect(folder)` comprueba identidad de caso y archivos privados, modos `0600/0700`, esquema JSON canónico, manifiestos SHA-256, encadenamiento del recibo `spent`, integridad de bytes F10, perfil y contadores F12. Rechaza sustituciones, entradas extra, manifestaciones de aprobación o candidatos con A6/generación fabricadas. Solo devuelve `RESERVED_NO_RETRY`, `ATTEMPT_CONSUMED_UNRESOLVED`, `RESULT_CANDIDATE_ONLY` o `FAILED_NO_RETRY`.

**Advertencia de fallo de lectura:** F12 cuenta una llamada `recv` fallida como recurso consumido; F10 contabiliza solo llamadas que devolvieron datos. Si ambos contadores difieren, F13 registra fallo terminal y **no admite** el resultado como candidato consistente. Esta divergencia fue encontrada mediante las pruebas F13, sin modificar F10 ni silenciarla.

## Límites de esta entrega

- La CLI `scripts/ardrec_p14_r115_f13_ftp_a5_journal.py` solo admite `--capabilities` o `--inspect-receipt` y **nunca reserva ni ejecuta**.
- No existe en F13 un despachador físico P8, una autorización externa autogenerada, un socket propio, un registro independiente de conexiones, ni un controlador root para abrir/cerrar el firewall.
- Un callback `current_p8_guard` que devuelve `True` **no constituye autorización criptográfica**. Los tests usan sockets simulados para ensayar la lógica, y los resultados siempre preservan `p8=NO-GO`, `a6=ND`, `a7/a8/a9/a10=null`, `physical_provenance_attested=false`.
- El diario es una capa de contabilización y procedencia **local**; los SHA-256 y los manifiestos protegen consistencia/reproducción, no impiden una sustitución coordinada por quien controle todos los archivos. La siguiente etapa deberá vincular recibos durables a testigos independientes y política root.
- No se modifica el catálogo original `lab/operational-catalog-v1/catalog.json` ni su estado `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`.

## Pruebas y salida

Prueba aislada: `PYTHONPATH=src:scripts python3 -m unittest discover -s lab/tests -p 'test_p14_r115_f13*.py' -q`.

Regresión que debe repetir Prometheus: R115 **338**, R112 **303**, R113 **350**, R114 **250**, total **1.241**. Los resultados offline no acreditan tráfico ni sondeos físicos.

**Siguiente integración:** raíz de confianza y autorización institucional independientes; piloto P7 físico bajo aprobación; ejecutor P8 de conexión única con testigo y atestación F11/R34; uso del diario F13 y posterior A6–A10 con hechos genuinamente acreditados. No equiparar un banner `220` con vulnerabilidad o recalibración confirmada.
