# R113-F10R — Reanudación segura tras normalización `chain="root"`

**Antecedente físico:** R113-F10, commit `b1e1fccebed9830a9250b8908d123cca0a567a04`, ejecutó exactamente seis `nwfilter-define` con código 0 pero se detuvo con `FILTER_DEFINITION_DRIFT_runner-ssh` antes de abrir tráfico. La inspección F10D (sesión `inspect-b8510sei`, reporte SHA-256 `1eca4123643f1900e417912cf55c69ffceeec1308b58a3dd03904597a2fc2cc1`) obtuvo seis diferencias de una sola clase: libvirt añadió `chain="root"` al elemento raíz `<filter>`. No hubo modificaciones de reglas ni de vínculos de red; F6 acreditó seis filtros DENY antes y después.

## Contrato de normalización

La comparación semántica de F10R descarta exclusivamente el UUID hijo inmediato generado por libvirt (máximo uno) y el atributo `chain="root"` **en el elemento raíz** cuando el candidato omitía `chain`. Comprueba nombre exacto, árbol completo ordenado, etiquetas, atributos de cada nodo y contenido significativo. Cualquier dirección, acción, IP, puerto, prioridad, orden, familia, subprotocolo o elemento adicional produce rechazo.

## Persistencia y no repetición

1. No repetir `nwfilter-define`, ni `APPLY_R113_F10.py`, ni staging F10. La definición histórica F10 y su marcador siguen preservados.
2. El nuevo root staging `/var/lib/ardrec/r113-f10r-window-v1` verifica el F10 root bundle con el propio `--check`, su marcador de intento de definición y la ausencia de intento de ventana. Verifica íntegramente el reporte F10D y exige exactamente una diferencia `chain="root"` por cada XML, además de las huellas F8R; copia solamente la política F8R/F9R previamente autenticada; toma el root operator y el verificador semántico desde Git HEAD firmado. El directorio root F10 original no se modifica.
3. `--adopt-filters` lee exclusivamente los seis filtros ya definidos mediante `nwfilter-dumpxml`, comprueba la equivalencia completa y los controles F11, watchdog y F6 DENY; no modifica firewall, libvirt ni VM. Genera un recibo y replay.
4. `--window` conserva el protocolo físico F10: primero F6 y preflight, luego armar temporizador independiente de 120s, sustituir seis bindings bajo R34 DENY, abrir R34 como última acción, hacer como máximo tres pruebas TCP limitadas sin autenticación, restaurar DENY en `finally` y acreditar las seis vinculaciones. Otra autorización explícita es obligatoria para esta operación.
5. Si un intento físico falla o queda incierto, no reintentar, no limpiar evidencias, acreditar manualmente las seis vinculaciones y revisar el temporizador según los registros.

## Condiciones de aceptación

- 653 regresiones (613 heredadas + 40 nuevas) y commit GPG válido, rama `feat/p14-r111-r114-real-lab` limpia.
- `R113_F10R_ROOT_BUNDLE=VERIFIED` y `R113_F10R_FILTERS=PASS_ADOPTED_EXISTING_NO_DEFINES` con replay.
- Antes de ventana `F6 --attest-deny` PASS. Para ventana física: temporizador realmente activo antes del primer cambio, políticas verificadas después de aplicar, evidencia QGA auténtica de runner y restauración F6 final independiente.
- P8 continúa NO-GO; sin push, merge, habilitación exterior, fuerza bruta ni enumeración no acotada.

**Interpretación:** la comprobación XML de F10D acredita semántica de filtros pero no permite inferir conectividad real, eficacia de respuesta protocolar, explotación o reducción de riesgo. Esas afirmaciones requieren resultados físicos de la ventana y aplicación de A1–A10 en R114.
