# ARDREC · R161 — Control monousuario de desarrollo, sin sustituir las guardas físicas

## Estado y objetivo

Base obligatoria: commit R149 `16a13a2b84ca6c5ba110820522146acadd856893`, árbol `7bf4da412b6ef6392b55bd5307cc4dd616863464`, rama de integración `feat/ardrec-cierre-operacional-experimental`, `main` inicialmente en `95a6d57b8241101c7a8fa3aedc07fb779b088d9f`.

La CLI admite también ejecución posterior desde `main` si su HEAD firmado incluye R149 como antecesor y el repositorio está limpio. No exige que `main` conserve su commit antiguo después de un merge.

Este lote no altera las fórmulas A1–A10, el catálogo de 25 familias, el diseño de 54 unidades ni R116-F1/F3, B4 V2, B9 V2, F7/F8 y R146. Añade un **plano de control para un único operador humano** y separa dos decisiones: incorporación del software a `main` frente a acreditación de pruebas físicas y validación académica externa. **No declara independencia humana donde no existe.**

## Componentes operativos

- `src/ardrec/coordination/r161_single_operator.py`: alcance de desarrollo autoatestiguado, identidad HEAD/árbol/boot/UID, caducidad máxima de diez minutos, JSON canónico, control de archivos `0700/0600`, una sola intención durable, verificación de preflight B9 y recibo B9 de restauración DENY.
- `scripts/ardrec_p14_r161_single_operator.py`: CLI `--capabilities`, `--prepare`, `--inspect` y `--pilot`. Solo la última opción puede delegar una acción al ejecutor root B9 ya instalado desde la ruta inmutable `/var/lib/ardrec/r128-one-session-v2/root-executor.py`; exige confirmación exacta y documentación root vigente y firmada **validada por el propio B9**. Nunca crea rutas root, abre sockets FTP por su cuenta, arranca huéspedes, modifica nft ni emite permisos B9.
- `lab/tests/test_p14_r161_single_operator.py`: pruebas de alcance, límite temporal, integridad, rechazo de suplantación, preflight, recibo y recuperación sin reintento. No ejecuta comandos root.

La autoatestación indica explícitamente `operator_mode=SELF_ATTESTED_DEVELOPMENT`, `independent_authority=false`, `independent_rubric_verified=false`, `grants_root_privileges=false`, `grants_network_traffic=false`, `grants_vm_start=false`, `p7=DRAFT_NOT_FROZEN`, `p8=NO-GO`, `a6=ND`, `a9=NOT_PUBLISHED`. No es permiso operacional. Las claves criptográficas de distintos roles pueden custodiarse técnicamente por una persona en un laboratorio de desarrollo, pero ello NO convierte esa persona en verificadores independientes ni altera las restricciones documentales de R146/B9.

## Ciclo de desarrollo

1. Integrar código bajo el usuario no privilegiado con 707/707 pruebas acumuladas, SHA del paquete, árbol limpio y commit firmado. No se crean sesiones ni se ejecuta `sudo` desde el aplicador.
2. Inspeccionar las capacidades desde el checkout limpio: `PYTHONPATH=src python3 -B scripts/ardrec_p14_r161_single_operator.py --capabilities`.
3. Para un futuro intento cuando **B9 raíz se haya instalado y aprovisionado correctamente**, identificar en la cadena B4/B9 la sesión hex de 16 caracteres ya autorizada y preparar el consentimiento local inmediatamente antes del intento:

   `PYTHONPATH=src python3 -B scripts/ardrec_p14_r161_single_operator.py --prepare --i-am-operator --session <sesion-16hex>`

4. Tras `sudo -v` interactivo, `PYTHONPATH=src python3 -B scripts/ardrec_p14_r161_single_operator.py --inspect --session <sesion-16hex>` verifica la liberación y revocación desde B9 sin cambios de estado. Si falta B9, el programa responde `B9_ROOT_EXECUTOR_ABSENT` y se detiene. Si está aprobado y hay margen de ventana, el operador podrá solicitar un único intento mediante `--pilot --session <sesion-16hex> --i-am-operator --confirm AUTORIZO_UN_INTENTO_FTP_T01_DESARROLLO`. NO iniciar este comando mientras el B9 original no esté acreditado.
5. El intento queda consumido antes de la llamada `--execute-pilot`. No hay reintentos automáticos. El recibo secundario verifica que B9 reportó `denies_restored_and_verified=true`, pero **no convierte una ejecución exploratoria en dato de tesis ni en revisión independiente**. En errores, expiración o tiempos límite, NO-GO y revisión manual de DENY.

**La CLI por sí sola no soluciona la ausencia actual de B4/B9 ni de las raíces de confianza**. Su función es proporcionar una ruta monousuario que reutiliza las barreras reales, sin reemplazarlas por una puerta trasera. Para la ejecución física, la provisión raíz y las autorizaciones vigentes deberán completarse honestamente bajo custodia del operador y con alcance de laboratorio. El texto de los contratos históricos que requiere revisión independiente sigue sin poder declararse satisfecho por autoatestación.

## Merge y límites académicos

Se puede **proponer un merge exclusivamente de código de desarrollo** tras la regresión, firmas, CI y revisión de seguridad, si el repositorio admite ese alcance. El merge no acredita por sí mismo Entrega A física, P8, FTP-T01 ni las 54 observaciones y debe conservar esas condiciones como pendientes. No se crea PR ni se ejecuta merge automáticamente. La validación por tres especialistas especificada en la tesis sigue pendiente.

Estado físico comprobado R151–R159: cuatro VM apagadas, seis filtros estructurales, Debian 13.7, OpenSSH 10.0p1, vsftpd 3.0.5, Samba 4.22.11+dfsg, tres archivos base de configuración recuperados, 25 familias documentadas, 54 posiciones sin seleccionar y cero observaciones. El bloqueo de B4/B9 root y permisos de arranque/tráfico sigue siendo real; un modo monousuario no debe alterar silenciosamente `P8=NO-GO`.
