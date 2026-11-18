# ARDREC R76 — Enlace conservador A5–A6–A7–A8 sobre recibo R75

**Estado:** modelo sintético offline; no autoriza P8, no acredita observaciones físicas.

R76 lee y valida el recibo R75 sin modificarlo; usa exactamente el modelo de intenciones y candidatos R59-D y el núcleo R58-E para construir 25 casos de familias P7 (SSH 8, FTP 8, SMB 9). Tres declaraciones exclusivamente simuladas (positiva, negativa, inconclusa) incluyen soporte y sellos temporales sintéticos para ejercitar el vínculo A5 y el hash de soporte. Las otras 22 son `NO_START` sin soporte. **No existen 25 ejecuciones A5 reales.** En R76 ni siquiera se lanza un subproceso benigno.

Los candidatos R59-D no constituyen admisiones técnicas R37, por lo que R58-E recibe cero admisiones, conserva 25 intervalos completos de incertidumbre y la clasificación A6 `ND` en todos los casos. A8 recomienda pausa, sin aplicar transiciones ni publicar generación adicional. `Rf` confirmado sigue nulo, `operational_dispatch=false` y P8 `NO-GO`. Tampoco existe un puente autorizado desde estas declaraciones a verdad técnica: simular un resultado positivo jamás debe rellenar Rf.

El reporte integra los hashes de R75 GEN1 y R71, los 25 enlaces entre familias/casos y la proyección conservadora de R58-E. El SHA-256 identifica el contenido, **no prueba autenticidad de una fuente externa**, firma, procedencia física o corroboración independiente.

## Uso, siempre desde el checkout canónico en Prometheus

```shell
cd /home/cicada/Development/GitHub/ardrec
python3 -B scripts/ardrec_p14_r76_a5_a8_offline_bridge.py --receipt-dir /home/cicada/ardrec-lab/r75-demo-20261118T035215Z-241956 --texto
python3 -B scripts/ardrec_p14_r76_a5_a8_offline_bridge.py --receipt-dir /home/cicada/ardrec-lab/r75-demo-20261118T035215Z-241956 --json > /home/cicada/ardrec-lab/R76_RESULTADO_TEMPORAL.json
chmod 600 /home/cicada/ardrec-lab/R76_RESULTADO_TEMPORAL.json
python3 -B scripts/ardrec_p14_r76_a5_a8_offline_bridge.py --receipt-dir /home/cicada/ardrec-lab/r75-demo-20261118T035215Z-241956 --verify-json /home/cicada/ardrec-lab/R76_RESULTADO_TEMPORAL.json
```

Se recomienda un directorio privado independiente 0700 para recibos de R76 y un manifiesto SHA separado. No introducir fuentes externas reales sin revisión de firma, procedencia, ventana, autoridad y controles F11. P7 sigue sin calibrar y P8 se mantiene en NO-GO.
