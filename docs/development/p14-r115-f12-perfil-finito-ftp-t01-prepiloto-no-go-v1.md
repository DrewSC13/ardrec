# R115-F12 — Perfil de recepción finito FTP-T01 y prepiloto no operativo

## Propósito

R115-F12 cierra una brecha entre F10 y F11: F10 limita el número de **bytes** recibidos y el tiempo, pero no impone directamente el número de llamadas `recv`. F11 declara `max_recv_calls` en la ventana firmada, sin poder aplicarlo a un socket ya conectado. F12 añade `MeteredSocket` que consume el presupuesto **antes de cada llamada**, incluyendo llamadas que acaban en error o tiempo de espera.

La entrega no es un controlador root P8, no concede permisos, no crea socket ni conecta a una IP. La instalación y el CLI nunca ejecutan tráfico, no arrancan máquinas y no mutan libvirt, nftables ni el catálogo. Las pruebas utilizan *sockets de prueba inyectados* sin tráfico físico. La integración real seguirá exigiendo al controlador externo autorización independiente A3/P8, guardas actuales y evidencia física inalterable.

## Contrato técnico del presupuesto

| Recurso | Cota candidata máxima F12 |
|---|---:|
| Conexiones | 1 (no verificable desde F12: la conexión la crea otro componente) |
| Intentos ordinarios | 1 |
| Reintentos | 0 |
| Tiempo total | 10 s |
| Bytes de recepción | 4.096 |
| Llamadas `recv` | 16 |
| Tamaño de cada `recv` | 512 B |
| Líneas | 16 |
| Tamaño de salida F10 serializada | 8.192 B |
| Memoria declarada | 512 MiB (la limitación real requiere ejecutor externo) |

Estas cotas deben reducirse cuando el contrato A3 o la ventana P8 impongan límites inferiores. `validate_profile` comprueba un contrato suministrado usando el verificador F11; nunca lo crea ni lo firma. `MeteredSocket` se interpone entre el socket previamente conectado y `F10.receive_control_reply()`, intercepta `recv` y `settimeout`, y rechaza llamadas fuera de presupuesto. Se contabiliza una llamada incluso si falla con timeout. `audit_f10_candidate` contrasta el resultado F10 con los contadores sellados, el presupuesto, la integridad y la clasificación de F11; su resultado sigue en A6 `ND` y P8 `NO-GO`. **El contador del decorador no acredita por sí solo el origen físico del socket**: falta vincularlo a un recibo externo real y firmado.

## Separación entre prepiloto y piloto verdadero

`prepilot_review()` comprueba que P7 conserve 25 familias (SSH 8, FTP 8, SMB 9), que FTP-T01 preserve sus cinco precondiciones, soportes y política sin mutación. Produce una **propuesta de perfil**, no una medición ni autorización. Su reporte declara explícitamente `pilot_completed=false`, `catalog_frozen=false`, `execution_enabled=false`, `a5=NO-GO`, `a6=ND` y `p8=NO-GO`. No existe ruta automática para cambiar esos valores.

Para completar el piloto real faltan: autoridad independiente y revocación; arranque controlado SSH, runner, FTP; verificaciones efectivas F11/R34 y seis vínculos activos; cliente/servicio/destino comprobados; sesión P8 autorizada y limitada; medidas físicas reproducibles del consumo y de resultados; decisión documentada de congelamiento de P7. Ninguno de esos requisitos es sustituido por pruebas de socket simulado.

## Ejecución

Desde el HEAD firmado y árbol Git limpio, sin sudo:

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 scripts/ardrec_p14_r115_f12_ftp_budget_preflight.py --review`

El recibo se crea privadamente bajo `/home/cicada/ardrec-lab/r115-f12-prepilot-v1/` con `report.json` y un manifiesto SHA-256. Se registran el HEAD, la huella exacta del catálogo y la huella del perfil propuesto. Ninguna operación sobre P7, las VM o la red forma parte del CLI.

Pruebas: `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 -m unittest discover -s lab/tests -p 'test_p14_r115_f*.py' -q`. También se exigen las regresiones R112, R113 y R114 antes de confirmar el commit. Los 40 casos F12 cubren sobrepresupuesto de llamadas, bytes, tiempo, salida, falsificación, origen y revocación de guardas; los resultados positivos son únicamente de **sockets inyectados**, no de FTP físico.
