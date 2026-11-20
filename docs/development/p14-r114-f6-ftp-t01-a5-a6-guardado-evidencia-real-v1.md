# R114-F6 — A5 físico FTP-T01 y vista trivalente A6 no ejecutable

## Alcance

R114-F5 realizó una única tentativa física FTP-T01 `ATT_R114_F5_FTP_T01_01` sobre `FTP-T01-S01-01`, runner `10.203.31.1` hacia `10.203.31.2:21`, con saludo `220`. F5C acreditó posteriormente el replay original y el estado DENY en seis bindings y cuatro reglas DROP, con hashes de actas conservados. R114-F6 **no repite la tentativa**.

R114-F6 importa por lectura privilegiada y estrictamente delimitada 16 archivos originales del recibo root F5, junto a seis piezas inmutables del cierre forense F5C y dos documentos F4 no privilegiados. El operador solo pide `sudo -v` y ejecuta `sudo -n /usr/bin/cat` sobre rutas absolutas fijas, sin ejecutar Python como root, sin invocar QGA, nftables, libvirt o systemd. Los ficheros confidenciales permanecen bajo `/home/cicada/ardrec-lab`, modo privado `0700/0600`, con sellado de sesión y replay offline.

## Validación

Exige el SHA-256 real del recibo F5 (`e80e6f33d7a82ac6e3c76bb70a262d0e65d2b4be0a7feb3558d0d2cd0711a742`), todos los hashes internos relativos a las fuentes copiadas, el F5C histórico (`replay.log`, DENY antes/después y R34 con cuatro DROP), el F4 original de configuración sin adjudicarle eficacia, el binario de salida QGA y su interpretación A5 mediante el módulo F5 firmado. También contrasta el XML de MAC de las VM, FTP-only en la ventana, F6 before/restore/attest, y el temporizador declarado activo.

El catálogo P7 SHA-256 `5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e` describe FTP-T01 con cinco precondiciones y tres soportes: `TARGET_ATTESTATION`, `INTEGRITY_PROVENANCE` y `CONTROL_CHANNEL_RESPONSE`. F6 identifica las tres fuentes candidatas **sin admitirlas automáticamente como A6**. El motor R58-I se evalúa en modo `SYNTHETIC_RULE_EVALUATION_ONLY`, con precondiciones A3 `ND` y resultado hipotético `NO_ADMITIDO/PRECONDITION_ND`; su salida no es una ejecución real A6, ni modifica P7 o A3.

## Cierre algorítmico

- A5: una tentativa física FTP-T01 observada y reproducida con procedencia verificable.
- A6: `ND`. No convertir un saludo `220` en vulnerabilidad.
- A7: sin Rf confirmado; A8: sin transiciones; A9: sin publicación.
- P7: `P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE`, sin promoción de política.
- P8: `NO-GO` permanente durante el incremento; Git privado, sin push ni merge.

## Ejecución y reversibilidad

El instalador agrega cuatro archivos de fuente, ejecuta regresión **859** y crea un commit firmado, solo si todo pasa. La fase física es **de lectura histórica exclusivamente** y requiere autorización independiente. El recibo y replay exigen hashes y comparación determinista. En fallo no reintentar automáticamente, ni reabrir F5.
