# ARDREC P14 · R58-F: doble testimonio Ed25519 para A6 (sin acreditación física)

**Base exacta:** PR #137 integrado en `main`, commit `8fb07df004b50627e8ba7bf310f637b78c07a28a`.

## Mejora funcional

R58-F introduce la admisión **criptográfica** de dos declaraciones sobre una misma observación. Los roles `observer` y `reviewer` deben usar identificadores y claves públicas Ed25519 diferentes; ambos deben firmar exactamente los mismos bytes canónicos prefijados. Los hashes SHA-256 de soporte y configuración, el servicio, caso y `assessment_index` se comprueban contra los valores esperados **que entrega el proceso llamador**. Se exige una captura anterior o igual al instante `as_of`, de antigüedad máxima de 24 horas.

Se utilizan `openssl pkey` y `openssl pkeyutl` exclusivamente offline para verificar Ed25519. No se usa `shell=True`, la ruta del binario es fija (`/usr/bin/openssl`), el proceso está acotado temporalmente y los datos de verificación se colocan en ficheros temporales privados. No se cambia la configuración de SSH, OpenSSL, libvirt, nftables, systemd ni VM. El flujo de demostración genera claves privadas **efímeras sintéticas** fuera del repositorio; no publica ni instala claves y no requiere privilegios.

Las claves `trusted_authorities` se introducen por un parámetro de confianza **separado del paquete documental**; el paquete no puede introducir sus propias claves. Estos registros de claves **deben proceder de una autoridad de registro de claves mantenida externamente y revisada**, no de la declaración no confiable. R58-F verifica que las declaraciones coinciden con los firmantes seleccionados, pero **NO autentica por sí mismo al responsable físico de la clave**, no prueba que ambos titulares sean independientes, no acredita el estado técnico del servicio ni demuestra una prueba experimental. Incluso cuando ambas firmas son válidas, la salida mantiene `a6_classification=ND`, `technical_truth_accredited=false`, `evidence_contribution=null`, `confirmed_rf=null`, ninguna transición y ninguna generación publicada. Un `MATCH` o `DIFF` firmado sigue siendo una afirmación no verificada.

La función `build_signed_bridge` enlaza los testimonios con las unidades del R58-E para SSH, FTP y SMB, incluyendo `assessment_index` y hash de configuración. Rechaza unidades ajenas, duplicados y firmas contradictorias. Reutiliza R58-E y R58-D sin alterarlos: las cotas A7 siguen siendo la envolvente matemática `UNRESOLVED [0,1]` y A8 solamente recomienda pausa.

## Verificación offline

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58f_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58f_signed_witness_demo.py --synthetic-offline
```

El ejemplo usa material sintético SSH y dos firmas efímeras verificadas, sin persistencia de recibos privados. Los ensayos adversariales cubren sustitución y reutilización de claves, firmas alteradas, discrepancias de soportes, ventana, configuración, identidad, método, rehash de falsificaciones, tipos de claves equivocados, duplicados y tentativa de promoción de riesgo.

## Límites y próximo paso

La doble firma ofrece **autenticación criptográfica relativa a claves públicas confiadas**, no es una validación científica del hecho observado. La futura acreditación técnica requiere proceso independiente comprobable de adquisición, registro de claves, autorización y contención F11; no queda habilitada por este PR. Las 54 unidades y 25 familias todavía carecen de aceptación experimental. `R34 DENY`, `P8=NO-GO`, `published_generation=null` y máquinas DEV apagadas se conservan.
