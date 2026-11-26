# R303 — Valoración documental del caso DEV / Documentary DEV assessment

## Español

`caso valorar-dev` incorpora una valoración documental al caso persistente R302.
`caso reabrir-valoracion-dev` reconstruye el mismo registro y verifica sus fuentes.
No modifica el caso original ni sustituye la línea base congelada. El resultado
reutiliza R199 y el núcleo de intervalos matemáticos R58-D, con pesos de referencia
1/3, 1/3, 1/3. No se acredita ninguna evidencia técnica: el intervalo de evidencia
permanece [0,1], la sustitución de referencia es R0 y el riesgo confirmado es ND.

El operador proporciona un directorio privado 0700 separado del origen y archivo
R302, con `ratings.json` canónico (UTF-8 ASCII escapado, claves ordenadas,
separadores compactos y salto de línea final) y un archivo 0600 `<sha256>.bin`
por cada soporte documental auténtico. Las huellas se verifican sobre bytes.
El JSON contiene exactamente `schema` (ARDREC-R303-DEV-ASSESSMENT-INPUT-v1),
`case_id`, `case_sha256` (huella interna del registro R302) y `ratings`.
Las seis claves de `ratings` son exposure, probability, impact,
operational_importance, data_sensitivity, dependencies. Cada una contiene
ordinal (entero 1–5), support_sha256 (64 hex minúsculas) y justification
(10–2000 caracteres tras quitar espacios). La exposición debe corresponder al
alcance planificado del escenario. Cada soporte admite hasta 200000 bytes.
La integridad no equivale a validación semántica o independencia de la fuente.

```
python -m ardrec caso valorar-dev --origen ORIGEN --archivo ARCHIVO --id ID \
  --sha256 HUELLA_ESCENARIO --valoracion DIRECTORIO \
  --sha256-valoracion HUELLA_RATINGS --texto
```

La reapertura usa las mismas opciones y `reabrir-valoracion-dev`. `--json`
produce el registro canónico. Se admite una valoración inmutable por caso:
una repetición idéntica es idempotente; cambios se rechazan, no sobrescriben.
El intervalo es hipotético y no representa una medición física, ni un Rf
operacional. Estado PREPARADO, A6 ND, A9 no publicado, P7 no congelado,
P8 NO-GO. No cierra AL-06 ni AL-07 ni admite observaciones experimentales.

## English

The normal case CLI attaches a source-bound documentary assessment to an
existing immutable R302 DEV case. It reuses R199 exact ordinal arithmetic and
R58-D mathematical intervals with reference weights 1/3 each. The ratings
file is pinned by its raw SHA-256; each private support file is hash-addressed.
Reopening checks the original case, all source bytes, support integrity and
assessment replay. Identical submissions are idempotent; changes are rejected.
The unknown evidence range stays [0,1]. The hypothetical interval is not
confirmed final risk. No dispatch, operational publication, frozen baseline,
formal pilot or experimental admission is granted. P8 stays NO-GO.
