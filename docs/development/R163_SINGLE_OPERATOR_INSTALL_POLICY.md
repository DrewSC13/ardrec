# R163 — Política de autorización monousuario

## Alcance

El perfil `ARDREC-R163-SINGLE-OPERATOR-INSTALL-POLICY-v1`
representa una autorización de desarrollo bajo custodia de una sola
persona. No afirma independencia humana ni admite firmas atribuidas
a terceros inexistentes.

La política autentica un documento de autorización y otro de
revocación mediante Ed25519. Verifica el UID, el identificador del
operador, la revisión y el árbol Git, la sesión, el arranque Linux,
el inventario, el paquete del agente y las huellas históricas
de B4 y B9.

## Límites

El resultado del validador NO concede acceso root. La procedencia
de las claves, el control de permisos del sistema, la instalación
privilegiada y el recibo físico deben verificarse por separado.

La autorización tampoco habilita tráfico, arranque de máquinas,
ejecución FTP, clasificación A6, publicación A9 ni admisión
experimental P8.

## Compatibilidad

Este módulo no modifica R146, R139, R161, B4 ni B9.

La integración operacional futura requiere un perfil versionado
del instalador y contratos B4/B9 compatibles con la custodia
monousuario. No se permite presentar las declaraciones históricas
de independencia como si hubieran sido acreditadas.

## Evidencia

Las pruebas incluidas utilizan claves temporales independientes
únicamente como material criptográfico de ensayo. No representan
firmantes humanos adicionales ni autorizaciones reales.

Estado: IMPLEMENTACIÓN DE POLÍTICA; NO-GO OPERACIONAL.
