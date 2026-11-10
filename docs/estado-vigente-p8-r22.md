# ARDREC — P8-R22: frontera estática de búsqueda del cargador

**Base exacta:** merge protegido R21 `0abec70380976b15a674580ab600f9bd933678c8` (PR #54), CI posterior `42726374468` aprobada.

R18–R21 aportaron tres binarios raíz, 138 bibliotecas ELF candidatas (68+64+6), 906 relaciones declaradas (292+563+51) y 66 objetos con avisos de rutas personalizadas (R19 incluido R18: 9; R20: 53; R21: 4). Esos números son **contabilidad estática candidata**, no equivalencia con `ld.so`. Los recibos R18, R19, R20 y R21 se mantienen privados y fijados mediante SHA-256.

R22 propone **reutilizar los cuatro recibos sin reabrir la QCOW2**. El analizador reconstruye la conciliación de R20 y R21, coteja la integridad del grafo y clasifica expresiones de `DT_RPATH` y `DT_RUNPATH`: segmentos absolutos, relativos, vacíos, parent traversal, tokens de expansión (`$ORIGIN`, `$LIB`, `$PLATFORM`) y símbolos no conocidos. Conserva los originales por objeto en un **nuevo recibo privado**; solo los agregados y el SHA del recibo pueden publicarse.

El objetivo es identificar los límites y riesgos documentales que bloquean una afirmación sobre búsqueda efectiva de bibliotecas. No implementa semántica `ld.so`, reglas de herencia de RPATH, alcance de RUNPATH, `ld.so.cache`, glibc-hwcaps, `LD_*`, preloads, versión ABI ni carga real. Tampoco acredita configuración efectiva, políticas CLI por perfil, autoridad ni pruebas de restauración.

**Estado:** P8 permanece abierto. Los 29 perfiles permanecen bloqueados y sin despacho; cero casos autorizados. AL-06/AL-07 y obligaciones materiales, incluidas cinco variantes de escritura, siguen abiertas. No adelantar P9 ni A1–A10.

**EN:** Signed receipt-only ELF search-path lexical audit and candidate graph reconciliation; no loader-equivalent resolution or operational authority.

## Resultado material R22 verificado por recibo autenticado

Auditoría privada R22 autenticada mediante SHA-256: **138 bibliotecas candidatas**, **906 relaciones estáticas**, **3 binarios raíz** y **66 entradas DT_RUNPATH de directorio absoluto**. No se observaron DT_RPATH en este conjunto; 9 entradas proceden de R19 incluyendo R18, 53 de R20 y 4 de R21. El recibo privado permanece fuera de Git.

SHA-256 del recibo R22: `3c67529808db1ab8ddc05f5e2cf9a4b0ce7d34ca4bcb0e28993c4cb0db200408`. No se accedió a la QCOW2 durante este incremento. La observación **no certifica** orden de búsqueda de ld.so, cache, hwcaps, entorno/preload, configuración ni identidad efectiva de runtime. Sin autorización de casos ni perfiles; sin despacho. P8 y AL-06/AL-07 siguen abiertos.
