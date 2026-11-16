# P14 / R58-Q — PREPARADO–PENDIENTE: auditoría lógica A3–A4

## Alcance

Se reutilizan los controles tipados R17–R22 asociados a 29 casos y 25 familias
por R58-P y la selección voraz exacta A4 de R27. Los 29 casos conservan la
misma sesión R26 y las identidades completas de R58-L. Se mantienen las fuentes
P7 (catálogo SHA-256 fijado) y tesis SHA-256 fijada.

## Doble evaluación — no confundir posibilidad con autoridad

1. **Estado presente (PREPARADO):** A4 evalúa exactamente los 29 candidatos,
   sin fase PENDIENTE. Resultado obligatorio: 0 elegibles y ninguna selección.
2. **Hipótesis lógica (PENDIENTE):** solo se permite proponer PENDIENTE cuando
   el control A3 de ese caso y su tabla sean VERDADERO, no existan bloqueos
   adicionales a AUTORIDAD_OPERACIONAL_NO_ACREDITADA, y su aplicabilidad
   sintética sea verdadera. No se aplica ninguna transición.
3. **Resultado de desarrollo esperado:** 8 casos SSH hipotéticamente elegibles,
   10 FTP con guarda ND y 11 SMB con guarda FALSO bloqueados. El candidato
   hipotético se obtiene con el selector voraz real, NO por un ranking nuevo.
4. **Contradicción detectada:** R58-L, al suponer PENDIENTE y guardas positivas
   para 29 casos, puede elegir una familia FTP. La evaluación A3 de la sesión
   actual NO habilita ese caso. Se conservan ambos informes con distinta semántica.

No existe un certificado de procedencia física, ninguna transición válida
PREPARADO→PENDIENTE, ni autorización para ejecución P8. Los guardas del
escenario R26 son exclusivamente hechos sintéticos de la sesión fija.

## Guardas y seguridad

La prueba rechaza identidades, variantes o precedencias cruzadas; reglas
alteradas; evidencias acreditadas falsamente; inicios de A5; cambios del
catálogo; informes modificados aunque se recalcule su SHA; y cambios de sesión.
Las salidas son deterministas, reproducibles e independientes del orden de
entrada aceptado por los componentes de origen. No se toca ni se escribe el
journal durable, la raíz del host, el entorno de las VM ni servicios SSH/FTP/SMB.

## Pendientes posteriores

Para cerrar la ruta operativa de A3–A4 hace falta una autorización explícita
independiente del escenario, pruebas de guardas de transición y autoridad,
registro de la transición confirmado, idempotencia de estado y conciliación del
presupuesto A5 con el caso físico. R58-Q no implementa esos requisitos.

**Invariantes:** R34 DENY; F11 no activado; P8 NO-GO; A6 ND; sin Rf confirmado;
sin transición A8 aplicada; sin publicación A9; hipótesis no validada.
