# ARDREC R163-F7 — Bootstrap V3

## Objetivo

Implementar un bootstrap versionado para publicar el agente
V3 de fuentes candidatas B4/B9 fuera del checkout mutable.

El incremento no habilita ejecución operacional.

## Reproducibilidad

El bootstrap mantiene fijados:

- Commit Git aprobado.
- Árbol Git aprobado.
- SHA-256 completo del ZIP F5.
- SHA-256 histórico de B4 V2.
- SHA-256 histórico de B9 V2.
- Inventario exacto de los siete archivos fuente.

La entrega de desarrollo se registra en un ZIP determinista.

## Rutas

Bootstrap externo:

/opt/ardrec/r163-bootstrap-v1/bootstrap.py

Paquete externo:

/var/lib/ardrec/r163-bootstrap-source-v1/agent.zip

Agente candidato:

/opt/ardrec/r163-installer-v1

Estado del staging:

/var/lib/ardrec/r163-stage-state-v1

## Acciones del bootstrap

--capabilities

Presenta capacidades sin privilegios.

--audit RUTA

Verifica el paquete ZIP, sus miembros, manifiesto
y huellas, sin instalar archivos.

--apply

Operación privilegiada separada. Solo puede utilizarse
tras aprovisionamiento externo, verificación de procedencia
y autorización específica. No se ejecuta en F7.

## Escritura segura

La operación de publicación requiere propietario root,
directorios protegidos, archivos exclusivos, permisos
0600/0700 y publicación atómica sin sobrescritura.

Ante un staging incompleto, la ejecución se detiene y
conserva la evidencia para revisión.

## Límites

La instalación del agente V3 no instala ni activa
los ejecutores B4/B9 V2.

Los documentos R163 de autorización y revocación
deben proporcionarse por un procedimiento separado.

No existe afirmación de independencia humana.

No se ejecutan máquinas virtuales ni tráfico FTP.

No se habilitan P7, P8, A6 o A9.

Estado: BOOTSTRAP FUENTE / SIN INSTALACIÓN FÍSICA.
