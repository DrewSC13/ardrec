# ARDREC R77 — Recepción documental firmada R76 → R58-F/G → A6–A8

**Base exacta:** `main` `719472fcfd96767e34992eb5d44170dfd63c1237` (merge del PR #170).

## Objetivo

Recibir testigos documentales externos firmados Ed25519 en los tres casos sintéticos ya declarados en R76, y enlazarlos con sus 25 intenciones A5 (SSH 8; FTP 8; SMB 9) y las 25 unidades A7. **No se crea un verificador criptográfico alternativo**: se invoca la verificación original R58-F (`r58f_signed_witness`), el registro de confianza R58-G (`r58g_trust_registry`, `r58g_registry_bridge`) y la validación de recibos R75/R76.

El proceso requiere las firmas de `observer` y `reviewer`, distintas claves Ed25519; registro externo con dos roles, alcance exacto de campaña/servicio/caso/ventana/configuración/método; vigencia temporal; revisión y revocación; identificadores históricos proporcionados por el llamador y un pin SHA-256 aportado **independientemente de los paquetes de declaraciones**. Una firma correcta atribuye una declaración a una clave, pero no prueba que la captura física haya ocurrido ni que los firmantes sean independientes en la realidad.

## Uso sin ejecutar A5

Entrada: `scripts/ardrec_p14_r77_signed_a5_a8_bridge.py`. Se requieren ficheros JSON canónicos (`sort_keys=True`, separadores compactos, `ensure_ascii=True`, `allow_nan=False` y un salto de línea final), regulares, `0600`, de un solo enlace, propiedad del operador y en un directorio padre `0700`. Las rutas absolutas no pueden contener enlaces simbólicos.

```shell
cd /home/cicada/Development/GitHub/ardrec
umask 077
python3 -B scripts/ardrec_p14_r77_signed_a5_a8_bridge.py \
  --receipt-dir /home/cicada/ardrec-lab/r75-demo-20261118T035215Z-241956 \
  --r76-report /RUTA_PRIVADA/r76.json \
  --registry-json /RUTA_PRIVADA/registry.json \
  --registry-pin-sha256 SHA256_OBTENIDO_POR_CANAL_INDEPENDIENTE \
  --bundles-json /RUTA_PRIVADA/signed-bundles.json \
  --prior-ids-json /RUTA_PRIVADA/prior-record-ids.json \
  --as-of-utc 2026-11-18T12:00:00Z \
  --json > /RUTA_PRIVADA/r77.json
```

No se suministran claves privadas ni se generan credenciales en producción. El archivo de paquetes es una lista (máximo tres elementos), cada uno con exactamente `statement`, `signatures`, `support_b64`; el último es el soporte binario codificado en base64 canónico. El registro contiene los 25 casos sintéticos de R76 y se comprueba contra el intento, configuración y método originales. No pueden introducirse nuevos casos ni alterar los tres resultados declarados por R76 (`MATCH` positivo, `DIFF` negativo, `INCONCLUSIVE` inconcluso). Estos tres son **simulados y no acreditados**. El historial de IDs también es un input externo; su autenticidad NO queda demostrada por esta función. R77 rechaza testimonios de casos `NO_START`.

Para reconstrucción estricta posterior sin escribir ni iniciar A5, sustituir `--json` por `--verify-json /RUTA_PRIVADA/r77.json`. Durante la verificación criptográfica, el código heredado R58-F/G invoca exclusivamente `/usr/bin/openssl` de forma acotada y sin shell; jamás despacha SSH/FTP/SMB, VM ni procesos A5.

## Pruebas

```shell
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r77_signed_a5_a8_bridge.py' -v
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r76_a5_a8_offline_bridge.py' -v
PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58g_*.py' -v
```

Las pruebas generan claves Ed25519 *efímeras exclusivamente dentro de directorios temporales privados*, sin exportarlas como claves de operación.

## Límites de autoridad

- `R77=DOCUMENTARY_ONLY`: la presencia de dos firmas verificables y de un registro que coincide con su pin es **atribución**, no acreditación física.
- `A6=ND`; las 25 unidades de R76 conservan intervalos A7 no resueltos, `Rf` confirmado `null`; A8 no aplica cambios; A9 no publica otra generación.
- `P8=NO-GO`; no se activan huéspedes, redes, filtros, servicios ni mecanismos F11.
- La procedencia **independiente** del pin y del historial de IDs es una obligación externa no satisfecha por R77; no afirmar que las pruebas sintéticas satisfacen esa obligación.
- Próximo paso físico: autorización separada, testigos independientes, cadena de custodia, acreditación F11/arranque manual y ejecución controlada SSH/FTP/SMB antes de publicar resultados empíricos.
