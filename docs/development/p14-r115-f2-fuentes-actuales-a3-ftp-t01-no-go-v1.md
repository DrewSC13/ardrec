# R115-F2 — Lecturas actuales A3 y negativa comprobable para FTP-T01

## Estado y relación con la tesis

Continúa R115-F1, en `feat/p14-r115-a3-p7-a6-real`, sobre `a652195a544a549dbad6a44120e3d447cf4d4994`. **Este incremento introduce medidas reales del anfitrión**, no una simulación de salida ni una autorización para tráfico. Los contratos matemáticos y la política de A3 exigen distinguir `VERDADERO`, `FALSO` y `ND`; F2 aplica únicamente **refutaciones observables y datos ND**, sin emitir por sí mismo ningún `VERDADERO` admisible para A5.

No toca P7 histórico, F1, R114, los contadores confirmados, las VM ni el estado durable A9. P7 sigue `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`; P8 `NO-GO`; A6 `ND`, riesgo A7 `null`, generación A9 `null`. No es aceptación operacional de A1–A10.

## Fuente real y controles técnicos

`r115_f2_a3_current_sources.py` captura en el **mismo anfitrión Prometheus**, utilizando comandos absolutos, parámetros estáticos, `virsh --readonly`, `subprocess.run(shell=False)`, entorno de localización `C`, 8 s máximos por lectura y límite de salida. No utiliza QGA, `virsh start`, `nft add/flush`, `systemctl start`, sockets de prueba, sudo, root ni una shell externa.

Lecturas exactas: estado de `ardrec-r33-dev-ftp` y `ardrec-r33-dev-runner`; XML de ambos dominios; XML e información de `ardrec-r33-dev-net-ftp`; tabla `bridge ardrec_r34_guard` en JSON; estado del temporizador `ardrec-r34-deny-watchdog.timer`. Se comprueban las definiciones de las NIC reutilizando R112-F1, identidad de red reutilizando R112-F4, cuatro reglas de denegación de R34 y carga/activación del temporizador. Errores por permisos, timeouts o lecturas truncadas devuelven **ND**, no éxito.

Las observaciones se guardan **privadamente** en `/home/cicada/ardrec-lab/r115-f2-a3-readonly-v1/capture-*`, directorio `0700` y archivos `0600` (`snapshot.json`, `report.json`, `manifest.json`). Cada fuente conserva código de retorno, salida original codificada en base64, stderr, fecha UTC y duración. El manifiesto incluye SHA-256 de los dos documentos. No se imprimen XML, rutas internas ni datos privados en el resumen de terminal. El hash acredita integridad de bytes, no autenticidad o autorización.

## Semántica de las cinco guardas A3

| Guarda | Comprobación F2 | Criterio de F2 |
|---|---|---|
| `SCOPE_APPROVED` | Contrato F1 opcional, catálogo, commit fuente y ventana UTC | Vencido/fuera de ventana = **FALSO**; ausencia de firmante independiente y revocación = **ND** |
| `LAB_ISOLATION_CONFIRMED` | XML sin forward/IP, identidad de red, estructura R34 y temporizador | Deriva técnica comprobada = **FALSO**; resultado coincidente o consulta incompleta = **ND**, falta acreditar seis bindings y aislamiento efectivo |
| `DESTINATION_AUTHORIZED` | MAC, NIC, dominio y red pinneados frente a R112 y contrato F1 opcional | Deriva comprobada = **FALSO**; coincidencia = **ND** hasta autorización explícita del destino |
| `CLIENT_COMPATIBLE` | No se inspecciona aún el cliente efectivo de un perfil ejecutable | **ND** siempre, nunca inferirlo de saludo `220` histórico |
| `SERVICE_READY` | Estado actual de las VM FTP y runner | Una VM apagada = **FALSO**; encendidas, desconocidas o fuente inaccesible = **ND** sin comprobación efectiva del servicio |

La matriz de resultados F2 no equivale a una decisión positiva A3 porque aún no existe un verificador independiente de autoridad, revocación, firma del perfil y supervisión real del ejecutor. Un texto de observación *autodeclarado* o un recibo importado **no** concede autorización; el módulo `report()` es puro para tests/replay y `--capture` realiza la adquisición de datos locales. El recibo no tiene carácter de lease vivo: cualquier cambio técnico exige una lectura nueva.

## Ejecución y regresión

El instalador de F2 exige la rama y HEAD exactos de R115-F1, los tres archivos F1 sin commit e intactos según SHA-256 de F1-R1, y ninguna otra modificación. Comprueba todas las entradas del ZIP, el manifiesto y cada hash antes de aplicar. Crea únicamente el módulo nuevo, su suite y esta documentación, sin sobrescribir. Ejecuta 23 pruebas R115-F2, 8 R115-F1 y 903 R112–R114. La adquisición del anfitrión al final es **solo lectura** y produce un recibo nuevo sin tocar los anteriores.

Comando posterior de solo lectura, si se requiere otra instantánea de la situación:

`PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:scripts python3 -m ardrec.coordination.r115_f2_a3_current_sources --capture`

Si existe un **contrato F1 privado realmente emitido** y con permisos adecuados, se puede adjuntar `--contract /ruta/absoluta/al/contrato.json`. No crear ni rellenar ese documento con referencias ficticias para conseguir un resultado verde. F2 exige que el commit fuente coincida con la base de R115 y no verifica todavía la firma de autoridad; por eso conserva NO-GO.

## Próximo incremento

F3: cadena de autorización independiente con firma y revocación verificadas, fuentes efectivas de las seis vinculaciones F11/R34, identificación del cliente y perfil/capacidad, preparación real del servicio, y presupuesto aplicable por A5. **Solo después**, en una acción autorizada específica, integrar admisión A6 y publicación durable A7–A10/TUI. No repetir el intento físico anterior por conveniencia. El cierre de F2 no supone aceptación de FTP-T01 ni cumplimiento de la hipótesis experimental.
