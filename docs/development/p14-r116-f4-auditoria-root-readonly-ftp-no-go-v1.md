# R116-F4 — Inventario operacional raíz FTP-T01, exclusivamente de lectura

## Propósito

R116-F3 ya contiene el controlador candidato, pero aún no ha sido desplegado ni acreditado. Este incremento verifica que las **31 fuentes del cierre F3** conservan SHA-256, y hace un inventario de presencia, propietario, tipo y permisos de los paquetes físicos R113/R114/F1/F3 y de las raíces de confianza y documentos del piloto. Es una **inspección de metadatos**, no una atestación criptográfica, no valida contenido root, no verifica firmas, no demuestra nftables ni comprueba el temporizador.

El resultado es siempre `NO-GO` para la ejecución física. Presencia no equivale a autorización. `UNKNOWN_ACCESS` no equivale a `ABSENT`. La interfaz no dispone de argumentos para abrir tráfico, ejecutar máquinas, instalar fuentes, armar temporizador ni cambiar reglas.

## Dependencias explícitas

- ROOT R113-F6 recuperador de seis vínculos (histórico) y R114-F5 material FTP; ambos son **prerrequisitos**, nunca ejecutados por F4.
- ROOT R116-F1 guardián DENY 5/1 (candidato sin stage atestado).
- ROOT R116-F3 controlador raíz y manifiesto (candidato sin stage atestado).
- Dos raíces de confianza, dos revocaciones actuales y tres documentos raíz de autoridad del piloto más referencia al arranque F8.
- Verificación física, autónoma e independiente de recuperación del temporizador mediante ensayo controlado por administrador autorizado; no se presume PASS.

## Método

1. Ejecutar el instalador de código fuente, regresión y commit firmado F4; no utiliza `sudo`.
2. Realizar la inspección CLI F4 no privilegiada del anfitrión: reporta los metadatos visibles y marca `UNKNOWN_ACCESS` si los directorios root no permiten lectura. El recibo se conserva en una carpeta privada nueva no versionada.
3. **Siguiente operación separada**: auditor/administrador independiente revisa físicamente root-owned stages, firmas y procedimientos antes de permitir stage o ejecución. Ningún resultado F4 puede usarse como permiso de A5, aceptación A6 o `P8=GO`.

F4 no ejecuta `R116-F3 --execute-pilot`, `R116-F1 --arm-deny`, `nft`, `virsh`, `systemd-run` ni las funciones `--stage-root`. Los estados se mantienen `P7=DRAFT_NOT_CALIBRATED`, `A6=ND`, `P8=NO-GO`.

## Próximos criterios de avance

- Si F1/F3 root staging figura `ABSENT` o `UNKNOWN_ACCESS`, hacer auditoría root separada. No arrancar VM para forzar los contadores.
- Si faltan firmas, autoridad o revocación, obtenerlas de firmantes externos independientes. No generarlas con la clave del propio operador.
- Antes de un piloto físico, medir restauración real de DENY, incluida caída del proceso y temporizador, con permiso del administrador del laboratorio; después verificar la secuencia real F7/F8 con condiciones de aislamiento.
- Solo las fuentes acreditadas deberán enlazarse mediante los recibos F13/F14 con el algoritmo A6; FTP `220` no es por sí solo evidencia de una vulnerabilidad.

**Cierre de F4**: aceptación del inventario reproducible y firma Git, no GO operacional.
