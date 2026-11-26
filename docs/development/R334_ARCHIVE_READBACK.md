# R334 — Lectura del archivo analítico instalado / Installed analytical archive readback

## Español

El archivo analítico nativo verifica ahora el conjunto exacto de nombres de la
instantánea: metadatos, manifiesto, proyecciones y objetos referenciados. Una
entrada ajena, incluso un directorio o un enlace, causa rechazo sin eliminación
ni reparación. La inspección del directorio tiene un límite implícito por el
conjunto ya validado; una entrada no esperada interrumpe la comprobación.
Se contrastan los metadatos de cada entrada antes y después de leerla y otra
vez al concluir la resolución. Tras instalar y sincronizar una instantánea
nueva, `store` reutiliza la recuperación nativa y exige igualdad de proyecciones
y referencias antes de devolver la huella. El formato y las huellas existentes
no cambian. La relectura añade trabajo de E/S, acotado por los límites previos.

Las pruebas de regresión R334 verifican rechazos sobre archivos temporales
reales, no sobre el laboratorio. Los errores conservan la instantánea para
diagnóstico e invalidan la sesión. No se garantiza atomicidad frente a cambios
concurrentes por el mismo UID, ni frescura externa ni durabilidad ante corte
eléctrico. No se interpretan cargas semánticas, no se acredita autoridad,
no se ejecutan protocolos ni se promueven P7/P8, AL-06 o AL-07.

## English

The native archive now checks the exact bounded inventory of installed entries,
rechecks file identity after resolving the complete reference set, and reads back
new snapshots before returning their digest. Unexpected entries cause rejection;
no deletion or repair is attempted. Existing snapshot formats and digest values
are unchanged. Tests use real temporary files. This does not prove atomicity
against same-UID changes, external freshness, power-loss durability, semantic
payload correctness, operational authority or experimental admission.
