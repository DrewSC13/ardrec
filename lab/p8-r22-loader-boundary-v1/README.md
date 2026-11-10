# P8-R22 — Auditoría offline de frontera de búsqueda ELF

Este incremento reduce una incertidumbre concreta de P8: separa la **cobertura de candidatos `DT_NEEDED`** de la semántica efectiva de carga. Contabiliza 3 raíces, 138 nodos candidatos y 906 relaciones candidatas a partir de recibos R18–R21 autenticados; identifica 66 objetos con `RPATH/RUNPATH` a clasificar, sin resolver dinámicamente su orden, ámbito ni variables de entorno.

- `lab/p8_r22_loader_boundary.py`: analizador puro, replay de R20/R21, contabilidad de aristas, clasificación lexical conservadora, guardas *fail closed*.
- `lab/p8_r22_private_audit.py`: lectura privada única de cuatro recibos previos, nuevo recibo R22 en modo 0600 (directorio 0700), sin sudo y **sin leer QCOW2**.
- `lab/verify_p8_r22_loader_boundary.py`: interfaz CI pública verificable; no accede a recibos ni material del laboratorio.
- `lab/tests/test_p8_r22_loader_boundary.py`: pruebas unitarias y de mutación de fronteras; ninguna herramienta invitada.

El operador puede ejecutar la adquisición R22 únicamente tras validar el ZIP y worktree aislado; no es necesaria confirmación de VM inactiva porque **no hay acceso a la imagen**. Si ya existe un recibo de salida, abortar sin sobrescribir. No ejecutar herramientas SSH, FTP, SMB, `ld.so`, `guestfish`, `virt-cat` ni redes. En la conversación compartir solo el resumen de salida y SHA-256, no el recibo.

**Criterio:** la ausencia de relaciones candidatas pendientes en siete directorios **no** demuestra cierre transitivo real, configuración efectiva, integridad de ejecución ni autoridad del caso. 29 perfiles bloqueados; P8 y AL-06/07 abiertos.
