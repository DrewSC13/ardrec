# P8-R5 — Observación de identidad de materiales, en fixtures sintéticos

## Español — alcance demostrable

Referencia: tesis ARDREC SHA-256 `6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72`, secciones **3.7.5** (integridad, seguridad, trazabilidad) y **3.9.2** (traductor de casos, ejecutable, argumentos, versiones, huellas, alcance). Base de desarrollo: `main` `2030ef4fe24e3595cfb365853912548ff3294056`, tras P8-R4. Los registros históricos se preservan; no reescribirlos para fingir que sus verificaciones anteriores sucedieron en el presente.

**Objeto:** construir un oráculo limitado, en Python, que observa *bytes reales de archivos de prueba creados en directorios temporales controlados por los tests* y comprueba su correspondencia con un SHA-256 y tamaño declarados. Contrasta un binario principal ficticio y sus auxiliares ficticios con una propuesta y una declaración de pin, ambas **no confiables**. El resultado deniega siempre autorización y despacho. El programa de línea de comandos no ofrece opción para escanear binarios del anfitrión, rutas arbitrarias ni dossiers privados.

### Controles concretos

1. Abrir el directorio de prueba y cada componente mediante descriptores y `O_NOFOLLOW`; rechazar componentes simbólicos, rutas relativas no canónicas y archivos no regulares.
2. Rechazar ruta, carpeta y objeto final fuera de la identidad y permisos sintéticos especificados; comprobar propietario UID del propio proceso; negar archivos con enlace duro múltiple, setuid/setgid y escritura de grupo/otros. Solo fixtures de hasta 1 MiB (tope de test, **no** límite operativo de binarios futuros).
3. Calcular SHA-256 **sobre los bytes leídos por descriptor**, no dar por verdadera una huella porque parezca un hex de 64 caracteres. Verificar tamaño exacto y metadatos antes/después del recorrido; contrastar nuevamente el nombre final dentro del directorio abierto.
4. Contrastar declaración principal y auxiliares, conteos, rutas, versiones **declaradas**, identidades sintácticas de caso/etapa/perfil y referencias de procedencia de etapa. Rechazar la duplicación o sustitución. Las versiones no se prueban ejecutando comandos.
5. Mantener separación **verificación de bytes**, **proveniencia y autoridad real**, **autorización por caso** y **capacidad de ejecución Rust**. Ni coincidencia SHA ni validez de formato garantizan inmutabilidad futura, procedencia, pertenencia al laboratorio ni versión efectiva.

### Límites e invariantes no resueltos

- Es obligatorio un origen confiable externo a Git para versiones, firmas, procedencia y autorizaciones privadas. El pin y la propuesta suministrados al oráculo NO acreditan confianza porque puedan coincidir entre sí.
- No se verifica el inode del archivo entre esta lectura y un proceso posterior; persisten riesgos de cambio TOCTOU. La transferencia de fd/capacidad a Rust, comprobación de montaje, LSM, privilegios, namespaces, permisos efectivos y vigilancia de revocación siguen **AL-07 abiertos**.
- Los 29 perfiles P8 siguen bloqueados; **cero binarios reales fijados**, cero casos reales, cero autorizaciones, cero despacho y cero laboratorios físicos inspeccionados. El supervisor Rust permanece deny-only. El piloto no fijó límites operativos.
- Ninguna validación de evidencias analíticas A6 ni determinación de exposición/riesgo se infiere de esta observación: **AL-06 abierto**. Las siete obligaciones residuales no cambian.
- El oráculo es sintético, local y de solo lectura; no incorpora rutas de ejecuciones, shell, red, VM, snapshots, gestión de secretos ni resultados experimentales.
- No se han verificado firmas/cadenas de suministro ni instalaciones reales, ni se han completado A1–A10 o la muestra de 54 unidades.

**Validador contractual:** `python3 lab/verify_p8_material_attestation.py` (revisa el estado documental y la fuente R4; no lee binarios de host).

**Pruebas sintéticas:** `python3 -m unittest discover -s lab/tests -p test_p8_material_attestation.py -v` (archivos de prueba temporales creados y retirados dentro de los tests).

## English

P8-R5 is a deliberately limited **test-owned temporary-file fd byte oracle**. It compares actual bytes and metadata against untrusted declarations, tests path hygiene, ownership and changes during observation, and ALWAYS denies operational approval. It is not a trusted executable resolver, binary provenance authority, signer verifier, process-launch gate, or physical lab check. P6/P7/P8 remain unchanged and all real material binding, approval and AL-06/AL-07 work remains pending.
