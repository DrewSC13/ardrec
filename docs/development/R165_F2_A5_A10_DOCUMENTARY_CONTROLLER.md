# ARDREC R165-F2 — Controlador documental A5–A10

## Objetivo

Integrar la comprobación de recibos F13/B9 mediante R129-B10 con la
verificación criptográfica documental R129-B11, y conservar una
barrera explícita frente a A6, A7 confirmado, A8 y A9.

Esta versión no es el ejecutor operacional completo A1–A10.

## Contratos reutilizados

- R129-B10: reconstrucción de diario F13, recibos B9 y QGA;
  verificación de identidad y rechazo de inconsistencias.
- R129-B10 `a9_barrier`: bloqueo previo al almacenamiento nativo.
- R129-B11 `signed_review`: revisión Ed25519 de origen, decisión
  técnica y revocación, sin acreditación root.
- R129-B12: cálculo/calibración documental, fuera de este
  controlador hasta disponer de la fuente A6 admisible.
- R129-B13/B15: ruta nativa de A8/A9; no se invoca desde F2.

## Flujo A5–A10

1. A5: reconstruir el intento y el recibo candidato.
2. A6: comprobar opcionalmente las firmas documentales.
3. A7: conservar Rf confirmado como no determinado.
4. A8: registrar que no existe transición operacional aplicada.
5. A9: demostrar que la publicación permanece bloqueada.
6. A10: registrar una cadena de seis eventos con SHA-256.

Cada evento contiene su ordinal, estado, fuente y hash previo.
La verificación reconstruye todo el expediente y comprueba
igualdad exacta, no solamente el hash declarado.

## Limitación científica

Una respuesta FTP `220` no acredita acceso autenticado,
vulnerabilidad, riesgo confirmado ni procedencia física.

Incluso tres firmas documentales Ed25519 válidas requieren
relectura root independiente, testigo R127 y autoridad vigente
para producir una admisión A6 operacional.

El algoritmo mantiene A6=ND, Rf no confirmado y A9 inexistente.
P7 sigue sin congelarse y P8 permanece NO-GO.

## Pruebas

Se cubren intentos completos e incompletos, firmas Ed25519,
revocación, relojes vencidos, identidad F13/B9, seis eventos,
replay determinista, alteraciones y prohibición de sockets y
DurableStore.

La suite usa exclusivamente datos sintéticos y diarios
temporales no privilegiados.

## Seguridad

El módulo no dispone de funciones para abrir tráfico,
modificar nftables, iniciar máquinas, instalar autoridad root
ni publicar generaciones nativas. No reemplaza B11/B15.
