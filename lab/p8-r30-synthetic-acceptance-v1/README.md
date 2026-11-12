# ARDREC — P8-R30: oráculos sintéticos de aceptación FTP/SMB

Implementa y comprueba **21 contratos de observación sintética** (FTP 10 y SMB 11) anclados a las declaraciones P8-R29. Los resultados no se interpretan como pruebas de ejecución ni se admite origen distinto de `DECLARED_SYNTHETIC_FIXTURE_ONLY`. Los valores permitidos son `PASS_SYNTHETIC`, `FAIL_SYNTHETIC` y `ND_SYNTHETIC`. Cada perfil exige exactamente sus soportes de aceptación, en el mismo orden, sin comandos, identidad, credenciales ni autorizaciones.

Se distinguen explícitamente TLS de **control/datos** FTP, **firma/cifrado** SMB, variante de **lectura/escritura** y **limpieza** para las cuatro variantes mutadoras FTP/SMB. Una observación `ND` o negativa no se convierte en éxito, y ni siquiera todos los `PASS_SYNTHETIC` representan capacidad runtime. Los 8 perfiles SSH permanecen fuera del oráculo R30 y sujetos a sus propias obligaciones; se conserva la matriz global de 29.

**Invariantes:** 348 campos materiales pendientes, 261 barreras probatorias runtime no verificadas, cinco variantes de escritura globales sin limpieza material independiente (cuatro FTP/SMB + una SSH), cero casos/perfiles autorizados y cero despachos. `evaluate_synthetic` siempre responde `DENY`, con `argv=None`, `spawn=False`, `proof_gates_closed=0`.

Pruebas source-only CI: `python3 -B lab/verify_p8_r30_synthetic_acceptance.py` y `python3 -B -m unittest discover -s lab/tests -p test_p8_r30_synthetic_acceptance.py -v`. Ninguna abre QCOW2, conecta servicios, inspecciona secretos o ejecuta clientes. P8 y AL-06/AL-07 siguen abiertos; P9 y A1–A10 sin comenzar.

**EN:** Exact per-operation FTP/SMB synthetic observation oracles. Inputs are fixture-only; neither symbolic positive results nor offline source provenance demonstrate runtime capability or authorize dispatch.
