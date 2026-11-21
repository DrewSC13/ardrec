# R121 — Expediente FTP-T01 conectado F13 → F14 → R58-E → A8 → auditoría A10

## Alcance implementado

1. **A5 / F13**: lee y vuelve a comprobar la reserva única, su consumo y los soportes candidatos almacenados; nunca abre socket, arranca VM ni modifica filtros. Cualquier recibo alterado o procedencia incompatible se rechaza.
2. **A6 / F14**: reproduce el dictamen con el catálogo P7 fijado por SHA-256. Si falta atestación física independiente, los tres soportes quedan sin admisión y A6 permanece `ND`, incluso ante un saludo FTP `220` completo.
3. **A7 / R58-E y R58-D**: exige magnitudes racionales explícitas para la misma ventana e identidad F13, calcula los límites exactos del riesgo y mantiene `Rf` confirmado sin valor. No acepta evidencia insertada desde el archivo de magnitudes.
4. **A8**: usa el dictamen conservador `PAUSAR_HASTA_EVIDENCIA_AUTORIZADA`, sin mutar el autómata autoritativo.
5. **A9**: deja constancia de que no existe una generación global nueva; el expediente privado R121 **no es** la publicación A9.
6. **A10**: genera 10 etapas encadenadas por hashes y un expediente inmutable de auditoría verificable contra los archivos F13 originales, con dos archivos protegidos (600) dentro de una carpeta privada (700).

## Entrada mínima

Es indispensable que exista **un directorio F13 auténtico, ya generado fuera de R121**. R121 no crea una nueva reserva ni consume otro intento. Se exige un archivo JSON canónico con las siete claves siguientes (ejemplo numérico **meramente ilustrativo**, no datos reales y no válido para afirmar riesgo confirmado):

```json
{"assessment_index":3,"case_id":"FTP_T01_S01_01","evidence":[],"initial_risk":"1/2","normalized_criticality":"1/3","replacement_risk":"1/4","service_id":"FTP_DEV"}
```

Los identificadores, el índice y los valores racionales deben corresponder a la unidad real declarada. No se infieren ni se sustituyen desde una captura de VMs. El origen del expediente F13 y las magnitudes se contrastan al reconstruir la cadena.

```
PYTHONPATH=src python3 -B scripts/ardrec_p14_r121_ftp_case_chain.py --capabilities
PYTHONPATH=src python3 -B scripts/ardrec_p14_r121_ftp_case_chain.py --build --journal /ruta/privada/F13/case-... --unit-file /ruta/privada/unidad.json --persist
PYTHONPATH=src python3 -B scripts/ardrec_p14_r121_ftp_case_chain.py --verify-report /ruta/privada/R121/audit-...
```

`--persist` genera **solo** un expediente histórico de auditoría, sin crear una generación A9. La ejecución física exige una autorización nueva y un contrato operacional publicado por otra ruta; las firmas antiguas y las capturas reproducidas no constituyen esa autorización. Todas las operaciones R121 se realizan con usuario no-root.

## Criterios de aceptación

- Reproducción determinista de F13, F14 y R58-E; identidad de caso/ventana sin ambigüedad; cálculo racional exacto sin valores inferidos.
- Hash de cada etapa enlazado a su fuente y al paso anterior, expediente privado recuperable por nueva reconstrucción desde el diario F13.
- Detección de adulteración de los datos de entrada, del candidato, del reporte, de manifiestos, de estados A6/A8 y de falsas publicaciones A9.
- 46 pruebas unitarias e integración, y regresiones previas del proyecto. CI obligatoria y protección de `main` antes del merge.

## Límites no cumplidos todavía

**R121 no completa una ejecución física A1–A10.** Faltan autorización P8 independiente y vigente, congelamiento P7 justificado por pilotaje, soporte físico aceptado por A6, cálculo Rf confirmado, una transición A8 autorizada y la publicación durable A9. No cambiar estos valores mediante parámetros o documentos introducidos por R121. El resultado `NO-GO` no acredita fallo ni éxito de una prueba física.
