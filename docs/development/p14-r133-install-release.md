# R133 — Admisión de liberación y recuperación privada

## Finalidad

Integra comprobación documental de liberación firmada Ed25519,
revocación y fuentes B4/B9 V2. Refuerza R132 para rechazar
la desaparición de archivos o directorios ya publicados.

## Fuentes fijadas

B4 V2:
f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8

B9 V2:
c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3

## Alcance de la revisión

La revisión valida nombres, tamaños, bytes de scripts,
manifiestos estructurales, firmas de documentos, vigencias,
vinculaciones y revocación declarada.

No valida todavía la semántica completa de los demás
documentos operacionales ni la procedencia independiente
de las claves públicas.

La exclusión de firmantes se comprueba únicamente contra
la lista documental suministrada, no contra un registro
root acreditado.

La coincidencia del HEAD y árbol declarados con un commit
Git firmado debe comprobarse en una fase posterior.

## Recuperación

R132 conserva journal, destinos y recibo.
La conciliación verifica los destinos ya publicados sin
recrear silenciosamente archivos desaparecidos.

Permanece un modelo privado, no una instalación root real.
El comportamiento tras pérdida de energía y operaciones
privilegiadas requiere pruebas específicas adicionales.

## CI

El workflow de Entrega A se limita a la rama de desarrollo.
No crea PR ni efectúa instalaciones privilegiadas.

## Estado

ROOT_INSTALL=NO
TRAFFIC=NO
A6=ND
A9=NO_ACREDITADO
P8=NO-GO

No emplear claves temporales de pruebas como confianza de producción.
