# ARDREC R113-F8R/F9R — Corregir XML ARP sin alterar la evidencia F8/F9

Estado inicial: F8 commit `0eb1d8dbb618de008d8b96c5c5b89c474c54b980`, 564 pruebas, política offline y replay correctos; F9 dio `BLOCKED_FIX_POLICY`, seis XML `nwfilter` rechazados, comprobación `nft --check` aprobada, y F6 DENY antes/después verificado. El recibo F9 original es `/home/cicada/ardrec-lab/r113-f9-policy-host-acceptance-v1/validation-xiu8v24h/report.json` con SHA-256 `5f492ab67002cd6d8ce4d898d09c3c59c3c9551e72c243f6ac41f0e2190ae03d`.

## Causa documentada

El XML ARP de F8 utilizó `srcipaddr` y `dstipaddr` (campos IP/TCP), donde las reglas del protocolo ARP de libvirt exigen `arpsrcipaddr` y `arpdstipaddr`. Se sustituyen **solo esos 12 pares de atributos** en las 12 reglas ARP de los seis filtros. Los elementos, direcciones, MAC, TCP, estados, prioridades y regla `drop` quedan iguales. El archivo candidato `nft` permanece idéntico, byte por byte. No se amplía ningún permiso.

Referencia normativa: https://libvirt.org/formatnwfilter.html (atributos ARP/RARP, `arpsrcipaddr`, `arpdstipaddr`).

## Trazabilidad y alcance

- El módulo F8 original permanece intacto. La nueva versión F8R genera un **recibo nuevo**, enlazado por SHA-256 al manifiesto original F8 y al informe de bloqueo F9.
- El replay F8 original debe continuar funcionando; F8R no borra ni modifica F8 o F9.
- F9R valida en modo lectura el nuevo recibo: F6 `--check-root-bundle`, F6 `--attest-deny` antes/después, `nft --check --file`, `virt-xml-validate` para los 6 XML.
- F9R guarda un informe de comandos, códigos de retorno, bytes y hashes. Su replay verifica el recibo sin llamadas al host.
- Queda prohibido ejecutar `nwfilter-define`, `nwfilter-binding-create`, `nft -f` sin `--check`, conectarse por TCP, instalar reglas permisivas o iniciar procesos de ataque durante F8R/F9R.
- No se ejecuta push ni merge. R34 permanece `DENY`; P8 se mantiene `NO-GO`.

## Acreditación exigida

`584` pruebas acumuladas, firma Git verificada y árbol limpio. F9R exige **seis XML aceptados** y `nft --check` aprobado; un recibo F9R con `BLOCKED_FIX_POLICY` no constituye aceptación. La apertura de red, el watchdog de ventana y los ensayos de protocolos se autorizan en una fase distinta.
