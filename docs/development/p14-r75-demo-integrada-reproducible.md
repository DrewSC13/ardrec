# ARDREC R75 — Demostración integrada reproducible A1–A10

**Clase:** incremento de software de desarrollo, sin ensayo físico ni autoridad P8.

## Alcance

La entrada `scripts/ardrec_p14_r75_integrated_demo.py` consolida seis ejecuciones
acotadas de funciones ya existentes: (1) R70 GEN1, (2) recuperación R70,
(3) A4 hipotético/A5 benigno local R71, (4) replay de R71 sin segundo inicio,
(5) síntesis A2 de 54 unidades y 108 referencias a casos y controles, y
(6) A6–A8 sintético de 29 ejemplos para 25 familias (SSH 8, FTP 8, SMB 9).
La TUI de tres paneles R38 se renderiza **sin abrir curses** en un archivo de texto
(152 columnas, 36 filas) además de su JSON verificado.

`--create` requiere un directorio nuevo con padre privado 0700 propiedad del
operador no root, crea dentro la sesión persistente y sus recibos. `--verify`
revalida los hashes de todos los archivos, los contratos y el enlace entre
GEN1/R71/R38, **sin lanzar ningún subproceso**. El directorio de creación parcial
no se reutiliza automáticamente después de un fallo. Se preservan los modos
originales de los artefactos inmutables (lectura 0400). SQLite puede crear
`benign/attempts.sqlite3` con 0600 (umask 077) o 0644 (umask 022):
**solo durante `--create`**, dentro del perímetro privado 0700, R75 comprueba
propietario, archivo regular, enlace único, tamaño y modo de origen, y normaliza
el archivo a **0600 antes del inventario SHA-256**. `--verify` nunca cambia
permisos y rechaza una posterior degradación a 0644. Así el recibo es portable
y fail-closed sin flexibilizar los permisos aceptados al verificar.

El manifiesto SHA-256 aporta detección de corrupción local, no certifica
un testigo independiente ni sustituye firma/procedencia técnica. La creación
pasa por ejecutables Python exactos, sin shell, red, comandos de host, root
ni acciones físicas. La prueba negativa comprueba rechazo de inventario y
salidas alteradas, además de impedir la reinvocación accidental de A5.

## Invariantes y límites académicos

- A1–A10 = demostración **sintética DEV**; `A6=ND` y `Rf` confirmado `null`.
- A7 `5/12` = exclusivamente oráculo hipotético; no resulta del proceso local.
- GEN1 = publicación analítica **estructural**, nunca GEN2 ni corroboración técnica.
- 54 unidades = escenario sintético separado de los 29 ejemplos y del escenario
  durable de tres servicios. No se unifican sus poblaciones experimentalmente.
- Catálogo P7 = borrador no calibrado; familias no ejecutables.
- TUI R38 = render y fuentes originales, sin nuevo motor alternativo.
- P8 = `NO-GO`; ninguna ejecución de SSH/FTP/SMB, VM, `libvirt`, nftables,
  `systemd` ni investigación física F11.

## Uso en Prometheus (solo desde repositorio canónico)

```shell
cd /home/cicada/Development/GitHub/ardrec
python3 -B scripts/ardrec_p14_r75_integrated_demo.py --create --receipt-dir /home/cicada/ardrec-lab/r75-demo-NUEVO
python3 -B scripts/ardrec_p14_r75_integrated_demo.py --verify --receipt-dir /home/cicada/ardrec-lab/r75-demo-NUEVO
cat /home/cicada/ardrec-lab/r75-demo-NUEVO/reports/r38_pantalla.txt | more
```

La protección real de arranque, la carga efectiva del hook y el watchdog
requieren autorizaciones y evidencia física **separadas**. Esta entrega no las
acredita ni las sustituye.
