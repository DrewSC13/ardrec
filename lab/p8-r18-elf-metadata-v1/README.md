# P8-R18 — metadatos ELF de tres ejecutables candidatos (lectura sin VM)

Este incremento añade una **adquisición privada opcional de evidencia real**, reutilizando
`verify_p8_material_inventory.py --offline-image` de R9, cuya lectura de la QCOW2 original
contrasta el hash, las 15 huellas candidatas y cuatro versiones de paquetes. Luego
`p8_r18_offline_collect.py` lee **solo** `/usr/bin/ssh`, `/usr/bin/curl` y
`/usr/bin/smbclient` a través de `sudo -n virt-cat --format=qcow2 -a` y calcula, en
memoria, PT_INTERP, DT_NEEDED, DT_RPATH y DT_RUNPATH con un analizador puro de ELF64
x86-64 little-endian. No instala, ejecuta ni configura binarios invitados y no conecta
servicios ni arranca las VM de ARDREC. Las herramientas guestfs pueden
levantar su appliance aislado para leer el disco, que no equivale a iniciar
el huésped operativo del laboratorio. La adquisición requiere permisos preexistentes
para las lecturas offline; no los crea ni intenta elevarlos silenciosamente.

En CI se comprueba el contrato estático R9/R17 y se ejecutan pruebas sintéticas del parser.
**La CI no dispone de la QCOW2 del operador y no acredita medición real.** La captura
real se conserva en una carpeta local privada fuera de Git, modo `0700`, con recibo
JSON de creación exclusiva `0600`; se publica solo el SHA-256 del recibo y los totales.

## Límites de certeza

- `DT_NEEDED` identifica bibliotecas **declaradas directamente**, no sus rutas reales,
  versiones, identidades, dependencias transitivas ni carga mediante `dlopen`.
- `PT_INTERP` es una ruta declarada, no una prueba de resolución del intérprete.
- El hash de una imagen base no demuestra identidad del binario en futuras ejecuciones.
- Nada demuestra configuración efectiva, semántica CLI, autorización privada ni
  presupuestos. Cero `argv` renderizable, perfiles autorizados, casos y despachos.
- Si la imagen R9 no coincide exactamente, el modo de adquisición falla cerrado.

El resultado permitirá decidir qué dependencias deben resolverse después sin crear
29 recorridos redundantes. P8 sigue abierto. P9 y A1–A10 no se inician.

**EN:** Read-only, bounded ELF direct-dependency inspection from the pinned offline
QCOW2, with private write-once receipt; no runtime attestation or dispatch.
