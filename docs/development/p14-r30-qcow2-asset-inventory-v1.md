# P14-R30 · Inventario de bases y overlays QCOW2 (solo lectura)

**Dependencia:** PR #95 de R29 debe estar integrado sobre PR #94. El commit R29
`66c108aea3085ab18fab75d62b556a0b3880e34d` debe ser el segundo padre
exacto de la nueva integración de `main` (merge, no squash).

## Funcionalidad verificable

Se consumen el informe local R29 de libvirt —con SHA-256 del archivo recibido y
firma interna de su JSON— y las cuatro rutas documentadas en el procedimiento
histórico `lab/services-v1/procedures/activation-r8.py`. El módulo usa
`os.lstat` por cada componente de la ruta, sin seguir enlaces simbólicos. Si
se confirma que un archivo regular está en una de las ocho rutas allowlist,
puede consultar **únicamente** `qemu-img info --output=json -f qcow2` con
20 segundos de límite. No se lee el contenido del disco ni se arrancan VM.

| Rol | Base histórica | Overlay histórico | Virtual GiB |
| --- | --- | --- | ---: |
| SSH | `v4/ssh-base.qcow2` | `v6/ssh-runtime.qcow2` | 8 |
| FTP | `v4/ftp-base.qcow2` | `v6/ftp-runtime.qcow2` | 8 |
| SMB | `v4/smb-base.qcow2` | `v6/smb-runtime.qcow2` | 12 |
| Runner | `v4/runner-base.qcow2` | `v6/runner-runtime.qcow2` | 24 |

El informe distingue ausencia, falta de permisos, enlaces simbólicos, permisos
incorrectos y metadatos QCOW2 inesperados. Al reunir los ocho archivos, exige
`qcow2`, tamaño virtual exacto, base sin backing file y overlay con backing
apuntando a la base esperada. Son comprobaciones **de metadatos**, nunca
acreditación de contenido o de cadena de custodia.

## Invariantes

- Sin `sudo`, sin invocaciones `virsh`, sin red, sin `qemu-img create`, sin escrituras.
- Sin confianza automática en el inventario previo: el R29 adjunto debe indicar
  ausencia de dominios/redes ARDREC, con archivo SHA-256 explícitamente fijado.
- La huella de base en `expected.json` corresponde a la observación **histórica**
  de R8, no a una lectura reciente de bytes.
- `can_restore = false`, `operational_dispatch = false`, `p8_operational = NO-GO`,
  `vm_started = false` y `final_risk = null` para cualquier entrada.
- Solo se publica software y oráculos; los informes del host quedan en recibos
  privados, no dentro del repositorio público.
- Prohibido ejecutar `activation-r8.py`, que fue un procedimiento de una sola vez.

## Pruebas y oráculos

```text
python3 -B -m unittest discover -s lab/tests -p 'test_p14_r30*.py' -v
python3 -B -m unittest discover -s lab/tests -p 'test_p14*.py'
python3 -B scripts/verificar_trazabilidad_actual.py
```

El modo `--historical-only` no llama a ningún proceso; el modo `--scan-host`
consulta archivos locales de forma acotada. El JSON del segundo modo incluye un
SHA-256 de sus propios campos y el SHA-256 exacto del informe R29 consumido.
Una lectura de `qemu-img` fallida se trata como no verificada.

## Siguiente dependencia

Si hay bases/overlays reconocidos, corresponde **R31**: verificación acotada
actual de bytes y procedencia, validación de capacidad del host, diseño de
restauración exclusiva y revisión de autorización. No se crea todavía el
ciclo operacional ni se habilitan controles del catálogo P8. El estado histórico
`R8 PASS` no se traslada automáticamente a una VM restaurada.
