# R162 — Conciliación de integridad R115 y procedencia R138

El gate R115-F17 mantiene inmutable su manifiesto histórico de 58 fuentes.
La variante F7 desarrollada en R138 se admite exclusivamente por una huella
SHA-256 adicional fijada y por coincidencia de la huella original en el lock.
No se admiten otros cambios, rutas ni excepciones generales.

- Origen histórico R115: `90086ec330b1b9513d096fa6996e7dfe994ba10511702d4becbcc1fddee3688d`.
- Derivado R138 verificado por objeto Git: `b8c538cbfb55689dd65dc3ed80f98efd28b9a207`.
- SHA-256 exacto del derivado: `bc1403601138e9e2c31bad6a7bc1603806e29cc2c65eb5ffd2e516c28df62e13`.
- HEAD base de la conciliación: `f6f86bfbe54439529d818d4ac1fd2f2f8fe66ea5`.

R138 conserva sus restricciones de rama/ancestros/firma/limpieza.
Este cambio afecta solo al gate de verificación offline; no instala root,
no inicia máquinas, no concede permisos ni cambia P7/P8/A6/A9.
