# P14-R35 — Contención deny-first instalada y topología libvirt inactiva

## 1. Base y objetivo

- Repositorio: `DrewSC13/ardrec`.
- Base exacta: `b9b52e6fc65415e939728b17366acb49d2551563` (merge de R34).
- Paquete fuente: `ARDREC_R32_R33_R34_RECIBOS_PARA_R35.tar.gz`.
- SHA-256 fijado: `58e7cf2f59dd97cab948c190d637b6ff8ee8f67b45400769fe0d97a9e8f2ea36`.
- Objetivo: instalar una única tabla nftables de familia `bridge`, definir el nwfilter de denegación total, definir tres redes libvirt y cuatro dominios persistentes, dejando todas las redes inactivas y todas las VM apagadas.

R35 es un incremento de despliegue físico acotado. No ejecuta pentesting ni valida el comportamiento de los servicios invitados.

## 2. Autenticación de fuentes

Antes de cualquier escritura, el ejecutor:

1. Verifica el SHA-256 externo del TAR.GZ y una lista cerrada de 24 miembros.
2. Rechaza rutas absolutas, `..`, enlaces simbólicos, hardlinks, dispositivos, FIFOs, duplicados y miembros no declarados.
3. Verifica el recibo R32, su digest interno y los cuatro roles.
4. Verifica el recibo R33, sus vínculos a R32 y los siete XML exactos.
5. Verifica el recibo R34, sus vínculos a R33, el filtro, la política nftables y los doce hashes del manifiesto `SHA256SUMS`.
6. Verifica el recibo histórico de host R34 y el resultado satisfactorio del CI de R34. El preflight R34 se trata como evidencia histórica, nunca como estado actual.

La cadena aceptada es R32 → R33 → R34. Una divergencia detiene R35 antes de modificar el anfitrión.

## 3. Preflight actual del anfitrión

R35 vuelve a comprobar, inmediatamente antes de instalar:

- Acceso no interactivo `sudo -n`.
- Consultas de solo lectura a `qemu:///system`.
- Ausencia de colisiones de nombres y UUID para dominios, redes y nwfilter.
- Ausencia de los seis nombres TAP y los tres bridges reservados.
- Ausencia previa de `bridge/ardrec_r34_guard`.
- Sintaxis de la política mediante `nft -c -f -`.
- Esquema libvirt de siete XML R33 y un XML nwfilter.
- Propietario, grupo, enlaces, permisos y hashes de los cuatro discos base, cuatro overlays padre y cuatro overlays nuevos.
- Formato QCOW2, tamaño virtual y cadena de backing de los doce archivos.

No se aceptan resultados históricos como sustitutos de estas observaciones actuales.

## 4. Secuencia de instalación

La secuencia es fija y se detiene ante el primer fallo:

1. Crear únicamente `table bridge ardrec_r34_guard` mediante el contenido autenticado `bridge-deny.nft`.
2. Leer de vuelta la tabla y comprobar que sus tres cadenas y cuatro reglas coinciden con la política autenticada.
3. Reconsultar el nombre y UUID del nwfilter, definir `ardrec-r33-block-until-containment` y leerlo de vuelta; debe descartar todo el tráfico de entrada y salida.
4. Para cada red, reconsultar nombre y UUID y definir `ardrec-r33-dev-net-ssh`, `ardrec-r33-dev-net-ftp` y `ardrec-r33-dev-net-smb`.
5. Recalcular los hashes y la cadena de backing de los doce QCOW2 inmediatamente antes de definir dominios; deben coincidir con el preflight. Comprobar nuevamente que los seis TAP y tres bridges siguen ausentes.
6. Para cada dominio, reconsultar nombre y UUID y definir `ardrec-r33-dev-ssh`, `ardrec-r33-dev-ftp`, `ardrec-r33-dev-smb` y `ardrec-r33-dev-runner`.
7. Leer de vuelta las definiciones y verificar las tres redes como `Active: no`, `Autostart: no`, y las cuatro VM como `shut off`, `Autostart: disable`.
8. Verificar que los TAP y bridges continúan ausentes y que la tabla nftables mantiene exactamente la política prevista.

El nwfilter se define antes de los dominios que lo referencian. Las redes se definen, pero no se inician. Los dominios se definen, pero no se arrancan.

## 5. Límites de seguridad

R35 no contiene ni invoca los siguientes comandos o acciones:

- `virsh start`, `virsh net-start`, `virsh autostart`.
- `virsh shutdown`, `destroy`, `undefine`, `net-destroy`, `net-undefine` o `nwfilter-undefine`.
- `nft flush ruleset`, `flush table` o reemplazo de tablas ajenas.
- Escrituras, recreación, conversión o modificación de QCOW2.
- Activación de bridges, redes, TAP o máquinas virtuales.
- Pentesting, despacho operacional o evaluación de riesgo final.

La única mutación de firewall permitida es la creación de la tabla `bridge/ardrec_r34_guard`, limitada a los seis nombres TAP declarados. La única mutación libvirt permitida son las ocho definiciones y el nwfilter especificados.

La tabla nftables es de ejecución actual (runtime). R35 no modifica `/etc/nftables.conf`, unidades systemd ni persistencia de firewall tras reinicio.

No existe rollback automático. Si se produce un fallo después de una escritura, se conserva el estado parcial para revisión; no se intenta limpiar, redefinir ni continuar. El resultado será `PARTIAL_NO_GO_REVIEW_REQUIRED` y P8 permanecerá NO-GO.

## 6. Ejecución local

Después de aplicar el paquete en un worktree limpio basado exactamente en R34:

```bash
python3 -B -m unittest discover -s lab/tests -p test_p14_r35_inactive_deployment.py -v
python3 scripts/verificar_trazabilidad_actual.py
python3 scripts/verificar_ci.py python
git diff --check
```

El job Python de GitHub Actions también ejecuta `test_p14_r35_inactive_deployment.py`; el PR no se acepta si esa prueba falla.

Después de integrar R35 en `main`, ejecutar primero el preflight actual:

```bash
sudo -v
python3 -B scripts/ardrec_p14_r35_inactive_deployment.py \
  --source-archive /home/cicada/Development/GitHub/ardrec-patches/ARDREC_R32_R33_R34_RECIBOS_PARA_R35.tar.gz \
  --receipt-dir /home/cicada/Development/GitHub/ardrec-patches/recibos-r35-preflight-$(date +%Y%m%d_%H%M%S) \
  --preflight-only
```

Solo si el preflight termina con `R35_PREFLIGHT=PASS`, ejecutar la instalación previamente autorizada:

```bash
sudo -v
python3 -B scripts/ardrec_p14_r35_inactive_deployment.py \
  --source-archive /home/cicada/Development/GitHub/ardrec-patches/ARDREC_R32_R33_R34_RECIBOS_PARA_R35.tar.gz \
  --receipt-dir /home/cicada/Development/GitHub/ardrec-patches/recibos-r35-install-$(date +%Y%m%d_%H%M%S) \
  --install-deny-first-inactive \
  --i-authorize-r35-installation
```

El ejecutor corre como usuario normal y utiliza `sudo -n` exclusivamente para los comandos allowlisted. No se debe ejecutar el script completo como root.

## 7. Criterio de aceptación

`DEPLOYMENT_COMPLETE_INACTIVE` requiere simultáneamente:

- Tabla nftables instalada y verificada.
- Un nwfilter deny-all definido y verificado.
- Tres redes definidas, inactivas y sin autoinicio.
- Cuatro dominios definidos, apagados y sin autoinicio.
- Los seis TAP y tres bridges reservados siguen ausentes.
- Ningún QCOW2 modificado.
- Ninguna red o VM iniciada.
- Ningún cambio de reglas globales ni de firewall ajeno a ARDREC.
- Recibos privados con hashes verificables.

Incluso con R35 aceptado, `P8=NO-GO`, `system_functional_acceptance=PENDING`, `experimental_validation=NOT_RUN`, `final_risk=null` y los hallazgos AL-06 y AL-07 permanecen abiertos.
