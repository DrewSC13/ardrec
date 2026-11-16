# ARDREC P14 / R58-G — Registro de confianza externo, vigencia y campañas A6

**Base exacta:** integración de R58-F mediante PR #138, commit `c11f32e06a64e36b2d7f6fcde7f0f04ba8986300`.

## Qué implementa realmente

1. `ardrec.evidence.r58g_trust_registry` exige un registro de confianza externo con dos roles (`observer`, `reviewer`), propietario y organización declarados distintos, claves públicas diferentes con validación criptográfica de formato Ed25519, fechas de alta, vigencia, revocación y ámbito de campaña por servicio/caso/ventana/configuración/método. Su contenido está fijado por un **SHA-256 confiable suministrado de manera independiente del paquete de testigos**. Se rechazan rutas simbólicas y registros guardados dentro de Git. El formato de archivo es JSON canónico y se rechazan claves JSON duplicadas.
2. `ardrec.coordination.r58g_registry_bridge` enlaza ese ámbito con los testigos firmados Ed25519 verificados por el código real R58-F. Un testigo no puede sustituir el registro, insertar claves de confianza, autorizar unidades ajenas, modificar el hash de configuración o usar una clave revocada/inválida. La verificación de vigencia se ejecuta para el instante de captura y el de revisión. El registro **no puede ampliar** la autorización del laboratorio.
3. Se acepta un conjunto previo de IDs de registros, pero dicho historial debe llegar desde un **registro persistente independiente**. La función es stateless: bloquea IDs ya conocidos, pero NO constituye por sí sola una defensa global contra replay entre procesos ni verifica la procedencia física de ese historial.
4. En R58-G solo se admite `DEV_TUTOR_001`, porque el puente anterior R58-F mantiene esa sesión fija. Se exige además `campaign_id == session_id`, porque R58-F firma `session_id` pero todavía **no firma un campo `campaign_id` independiente**. Esa equivalencia impide atribuir a una campaña distinta una sesión firmada con otro identificador. En el futuro, un contrato v2 deberá firmar campaña, credencial de autorización y demás metadatos operacionales de forma explícita.

## Límite de autoridad, no negociable

La verificación SHA-256 del registro no prueba quién lo publicó: el pin debe provenir de una autoridad exterior confiable y revisada. La diferencia declarada de propietarios y organizaciones tampoco prueba que sean físicamente independientes. Revocaciones retroactivas y autenticidad de eventos requieren gobernanza adicional. Una firma Ed25519 valida autenticidad **relativa a esa clave**, no la verdad del hallazgo ni el aislamiento del laboratorio.

Este incremento solo admite documentos para revisión. Conserva `a6_classification=ND`, `technical_truth_accredited=false`, `confirmed_final_risk=null`, `applied_state_transition=null`, `published_generation=null`, `operational_dispatch=false`, `p8_operational=NO-GO`. Todos los cálculos A7 siguen siendo intervalos completos de incertidumbre y A8 continúa siendo una recomendación. No se crea ninguna generación A9.

## Verificación offline

```bash
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58g_*.py' -v
PYTHONPATH=src python3 -B scripts/ardrec_p14_r58g_trust_registry_demo.py --synthetic-offline
```

El CLI genera claves privadas **solo en un directorio temporal sintético**, las utiliza para firmar y las elimina al salir. En esa demostración, el pin se calcula localmente a modo de fixture: **no debe reutilizarse ese procedimiento como anclaje de confianza en operación real**. No se contacta a SSH, FTP, SMB ni a libvirt; no se modifica nftables, systemd, el host ni la máquina de estados.

## Próxima dependencia real

Para avanzar de atribución a acreditación de A6 se requieren: aprobación independiente y firmada del registro de claves, proceso físico de adquisición controlado, verificación de independencia de observadores, pruebas F11 de primer arranque y aislamiento, catálogo técnico de criterios por servicio y trazabilidad de cada condición. Las 54 unidades y 25 familias continúan sin aceptación experimental. P8 sigue `NO-GO`.
