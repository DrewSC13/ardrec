# ARDREC P14 / R60-E2 — Vinculación de casos modelo A4 ↔ A6–A8

## Alcance implementado

R60-E2 ejecuta de nuevo **una sola vez el contrato R58-L real** con su
fixture existente de 29 unidades modelo (SSH 8, FTP 10, SMB 11). El propio
R58-L consume `R58-K` y verifica su modelo. El nuevo módulo exige
coincidencia exacta entre el SHA-256 del informe unificado incorporado en
R58-L y el SHA-256 de R58-K recuperado de los tres logs R60-E0, autenticados
en R60-E1-R2.

Se cotejan individualmente 29 identidades completas:
`(service_id, session_id, derived_case_id, assessment_index)`,
`family_id`, `variant`, `case_id_a7`, selección A4, clasificación simulada,
cotas A7 y recomendación conservadora A8. Se lee el escenario R26 original
y se verifica su cadena de nueve eventos A1–A3; la asociación con cada caso
es **contexto por servicio, no autorización de control A3 vinculada al caso**.

El resultado es `case_ledger.json`, canonizado con SHA-256, y un manifiesto
privado almacenado bajo `/home/cicada/ardrec-lab/r60e2-*`, con permisos
0700 para el directorio y 0600 para los archivos. La demostración incorpora
el registro de etapas A1–A10 con *scope* explícito para impedir afirmar una
única sesión operacional completa.

## Fuentes y anclas

- Git `HEAD`: `ce9478eb04fb9e6607af534fa415542e7cbf24cd`.
- R60-E1-R2: `/home/cicada/ardrec-lab/r60e1r2-rrm9eg5z/integrated.json`.
- SHA-256 de este informe: `8549b011224e19b6066a77c547e0c623ceced3a77ca7866aaf9899b0de5184f7`.
- R58-K, R58-L y el escenario R26 se reabren en el checkout original.
- Los tres archivos R60-E1 ya instalados siguen intactos y sin commit.

## Ejecución con autoridad restringida

1. Instalar los tres archivos nuevos solo con aprobación explícita en terminal.
2. Ejecutar 60 pruebas negativas/positivas del nuevo contrato.
3. Ejecutar el modelo existente y guardar **solo el ledger privado**.

No se escriben los archivos de fuente anteriores ni se crean commits/PR.
No se ejecuta `sudo`, `systemctl`, `virsh`, `nft`, procesos invitados o tráfico
SSH/FTP/SMB. Las escrituras son solo la instalación de código fuente
explícitamente autorizada y la evidencia privada.

## Límites científicos, sin atribuciones indebidas

- **29 casos simulados** con 25 familias: ahora hay vínculo A4 ↔ A6–A8
  demostrado por identidad y SHA del mismo modelo, no tres conteos solamente.
- **54** es la cota del modelo: faltan 25 definiciones/casos auténticos del
  diseño experimental; R60-E2 **no los crea** ni los da por ejecutados.
- A1–A3 son tres servicios de la sesión R26, no controles A3 firmados
  sobre cada caso A4/A5. R58-V y R58-O siguen conciliados agregadamente,
  sin vínculo individual independiente.
- A5 físico=NO; A6 acreditado=`ND`; `Rf` confirmado=null; A8 sin
  transiciones reales; A9 sin generación publicada; P8=`NO-GO`.
- La validez matemática/algorítmica de la tesis y la hipótesis experimental
  **no se declaran validadas** por esta prueba sintética.

## Próximo incremento

Preparar el inventario auténtico de las 54 unidades con esquema y auditoría
caso por caso, incluyendo variantes, índices de evaluación y vínculos A1–A3;
rechazar duplicados, ambigüedades y ausencias antes de aceptar una supuesta
cobertura de 54. Mantener el despacho físico bloqueado hasta P8 independiente.
